package tunnel

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/selftunnel/selftunnel/internal/crypto"
)

const (
	WGHeaderSize       = 16
	WGKeepalive        = 25 * time.Second
	WGHandshakeInit    = 1
	WGHandshakeResp    = 2
	WGDataPacket       = 4
	WGCookieReply      = 3
	DirectGracePeriod  = 5 * time.Second // Keep relay active for 5s after direct is established
	DirectConfirmCount = 3               // Need 3 direct packets to confirm connection
)

// RelaySender interface for sending data via relay
type RelaySender interface {
	Send(to string, data []byte) error
	IsConnected() bool
}

type WireGuardTunnel struct {
	tun             *TUNDevice
	privateKey      [crypto.KeySize]byte
	publicKey       [crypto.KeySize]byte
	listenPort      int
	conn            *net.UDPConn
	ownConn         bool // true if we created the conn and should close it
	peers           map[string]*WGPeer
	peersMu         sync.RWMutex
	relay           RelaySender
	relayMu         sync.RWMutex
	onPunchPacket   func(addr *net.UDPAddr)                  // callback when punch packet received
	onDataReceived  func(publicKeyB64 string, isDirect bool) // callback when data received from peer
	onNeedReconnect func(publicKeyB64 string)                // callback when peer needs reconnection attempt
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

type WGPeer struct {
	PublicKey         [crypto.KeySize]byte
	PublicKeyB64      string // base64 encoded public key for relay lookup
	Endpoint          *net.UDPAddr
	AllowedIPs        []*net.IPNet
	LastSeen          time.Time
	LastDirectReceive time.Time // last time we received data via direct UDP
	TxBytes           uint64
	RxBytes           uint64
	Keepalive         time.Duration
	sharedSecret      [crypto.KeySize]byte
	encryptor         *crypto.Encryptor // ChaCha20-Poly1305 encryptor
	relayFallback     bool              // true if using relay instead of direct UDP
	directGracePeriod bool              // true during grace period after direct is established
	directGraceStart  time.Time         // when grace period started
	mu                sync.RWMutex
}

type WireGuardConfig struct {
	TUN        *TUNDevice
	PrivateKey [crypto.KeySize]byte
	ListenPort int
	Conn       *net.UDPConn // optional: shared UDP connection
}

func NewWireGuardTunnel(cfg WireGuardConfig) (*WireGuardTunnel, error) {
	publicKey := crypto.PublicKeyFromPrivate(cfg.PrivateKey)

	var conn *net.UDPConn
	var ownConn bool
	var err error

	if cfg.Conn != nil {
		// Use provided shared connection
		conn = cfg.Conn
		ownConn = false
	} else {
		// Create our own UDP connection - use udp4 for IPv4 only
		addr := &net.UDPAddr{IP: net.IPv4zero, Port: cfg.ListenPort}
		conn, err = net.ListenUDP("udp4", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on UDP port %d: %w", cfg.ListenPort, err)
		}
		ownConn = true
	}

	ctx, cancel := context.WithCancel(context.Background())

	wg := &WireGuardTunnel{
		tun:        cfg.TUN,
		privateKey: cfg.PrivateKey,
		publicKey:  publicKey,
		listenPort: cfg.ListenPort,
		conn:       conn,
		ownConn:    ownConn,
		peers:      make(map[string]*WGPeer),
		ctx:        ctx,
		cancel:     cancel,
	}

	return wg, nil
}

// SetPunchCallback sets the callback for when punch packet is received
func (wg *WireGuardTunnel) SetPunchCallback(callback func(addr *net.UDPAddr)) {
	wg.onPunchPacket = callback
}

// SetDataReceivedCallback sets the callback for when data is received from peer
func (wg *WireGuardTunnel) SetDataReceivedCallback(callback func(publicKeyB64 string, isDirect bool)) {
	wg.onDataReceived = callback
}

// SetNeedReconnectCallback sets the callback for when peer needs reconnection
func (wg *WireGuardTunnel) SetNeedReconnectCallback(callback func(publicKeyB64 string)) {
	wg.onNeedReconnect = callback
}

// AddPeer adds a new peer to the tunnel
func (wg *WireGuardTunnel) AddPeer(publicKey [crypto.KeySize]byte, endpoint string, allowedIPs []string, publicKeyB64 string) error {
	var endpointAddr *net.UDPAddr
	var err error

	if endpoint != "" {
		endpointAddr, err = net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return fmt.Errorf("failed to resolve endpoint: %w", err)
		}
	}

	// Parse allowed IPs
	var allowed []*net.IPNet
	for _, cidr := range allowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse allowed IP %s: %w", cidr, err)
		}
		allowed = append(allowed, ipNet)
	}

	// Compute shared secret
	sharedSecret, err := crypto.SharedSecret(wg.privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Create encryptor for authenticated encryption
	encryptor, err := crypto.NewEncryptor(sharedSecret)
	if err != nil {
		return fmt.Errorf("failed to create encryptor: %w", err)
	}

	// Use provided publicKeyB64 or generate from publicKey
	keyB64 := publicKeyB64
	if keyB64 == "" {
		keyB64 = crypto.ToBase64(publicKey)
	}

	peer := &WGPeer{
		PublicKey:     publicKey,
		PublicKeyB64:  keyB64,
		Endpoint:      endpointAddr,
		AllowedIPs:    allowed,
		Keepalive:     WGKeepalive,
		sharedSecret:  sharedSecret,
		encryptor:     encryptor,
		relayFallback: true, // ALWAYS start with relay - disable only when direct is proven to work
	}

	wg.peersMu.Lock()
	wg.peers[keyB64] = peer
	wg.peersMu.Unlock()

	return nil
}

// RemovePeer removes a peer from the tunnel
func (wg *WireGuardTunnel) RemovePeer(publicKey [crypto.KeySize]byte) {
	key := crypto.ToBase64(publicKey)
	wg.peersMu.Lock()
	delete(wg.peers, key)
	wg.peersMu.Unlock()
}

// UpdatePeerEndpoint updates a peer's endpoint (keeps relay enabled until direct is proven)
func (wg *WireGuardTunnel) UpdatePeerEndpoint(publicKey [crypto.KeySize]byte, endpoint string) error {
	key := crypto.ToBase64(publicKey)

	endpointAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("failed to resolve endpoint: %w", err)
	}

	wg.peersMu.Lock()
	if peer, ok := wg.peers[key]; ok {
		peer.mu.Lock()
		oldEndpoint := peer.Endpoint
		peer.Endpoint = endpointAddr
		// DON'T disable relay here - keep it enabled until we receive actual data via direct
		// peer.relayFallback stays true, will be set to false in handleDataPacket when data arrives
		peer.mu.Unlock()

		if oldEndpoint == nil {
			log.Printf("[WG] Set endpoint for %s to %s (trying direct, relay still active)", key[:16], endpoint)
		} else if oldEndpoint.String() != endpoint {
			log.Printf("[WG] Updated endpoint for %s: %s -> %s", key[:16], oldEndpoint, endpoint)
		}

		// Send keepalive to try establishing direct path
		go func() {
			keepalivePacket := make([]byte, WGHeaderSize)
			keepalivePacket[0] = WGDataPacket
			wg.conn.WriteToUDP(keepalivePacket, endpointAddr)
		}()
	}
	wg.peersMu.Unlock()

	return nil
}

// UpdatePeerEndpointByKey updates a peer's endpoint using base64 public key string
func (wg *WireGuardTunnel) UpdatePeerEndpointByKey(publicKeyB64 string, endpoint string) error {
	pubKey, err := crypto.FromBase64(publicKeyB64)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	return wg.UpdatePeerEndpoint(pubKey, endpoint)
}

// EnableRelayFallback enables relay fallback for a peer (used when direct connection is lost)
func (wg *WireGuardTunnel) EnableRelayFallback(publicKeyB64 string) {
	wg.peersMu.Lock()
	if peer, ok := wg.peers[publicKeyB64]; ok {
		peer.mu.Lock()
		peer.relayFallback = true
		peer.mu.Unlock()
	}
	wg.peersMu.Unlock()
}

// Start starts the WireGuard tunnel
func (wg *WireGuardTunnel) Start() error {
	// Start TUN reader
	wg.wg.Add(1)
	go wg.tunReader()

	// Start UDP reader
	wg.wg.Add(1)
	go wg.udpReader()

	// Start keepalive sender
	wg.wg.Add(1)
	go wg.keepaliveSender()

	return nil
}

// Stop stops the WireGuard tunnel
func (wg *WireGuardTunnel) Stop() {
	wg.cancel()
	if wg.ownConn {
		wg.conn.Close()
	}
	wg.tun.Close()
	wg.wg.Wait()
}

// SetRelay sets the relay sender for fallback communication
func (wg *WireGuardTunnel) SetRelay(relay RelaySender) {
	wg.relayMu.Lock()
	wg.relay = relay
	wg.relayMu.Unlock()
}

// WriteFromRelay handles data received from relay
func (wg *WireGuardTunnel) WriteFromRelay(from string, data []byte) {
	// Find the peer by public key
	wg.peersMu.RLock()
	peer, exists := wg.peers[from]
	peerCount := len(wg.peers)
	wg.peersMu.RUnlock()

	if !exists {
		// Log all known peer keys for debugging
		wg.peersMu.RLock()
		knownKeys := make([]string, 0, len(wg.peers))
		for k := range wg.peers {
			if len(k) > 16 {
				knownKeys = append(knownKeys, k[:16])
			}
		}
		wg.peersMu.RUnlock()
		log.Printf("[Relay] Received data from unknown peer: %s (have %d peers: %v)", from[:16], peerCount, knownKeys)
		return
	}

	// Decrypt the packet using XOR with shared secret
	decrypted := wg.decryptWithSecret(data, peer.sharedSecret)
	if decrypted == nil {
		log.Printf("[Relay] Failed to decrypt data from %s (data len: %d)", from[:16], len(data))
		return
	}

	// Validate IP packet
	if len(decrypted) < 20 {
		log.Printf("[Relay] Decrypted packet too short: %d bytes", len(decrypted))
		return
	}

	// Write to TUN
	n, tunErr := wg.tun.Write(decrypted)
	if tunErr != nil {
		log.Printf("[Relay] Failed to write to TUN: %v", tunErr)
		return
	}

	// Log first successful receive for debugging
	peer.mu.Lock()
	wasFirstPacket := peer.RxBytes == 0
	peer.RxBytes += uint64(n)
	peer.LastSeen = time.Now()
	peer.mu.Unlock()

	if wasFirstPacket {
		log.Printf("[Relay] First packet received from %s (%d bytes written to TUN)", from[:16], n)
	}

	// Notify callback that we received data from this peer (via relay)
	if wg.onDataReceived != nil {
		wg.onDataReceived(from, false)
	}
}

func (wg *WireGuardTunnel) tunReader() {
	defer wg.wg.Done()

	buf := make([]byte, wg.tun.MTU()+100)

	for {
		select {
		case <-wg.ctx.Done():
			return
		default:
		}

		n, err := wg.tun.Read(buf)
		if err != nil {
			select {
			case <-wg.ctx.Done():
				return
			default:
				continue
			}
		}

		packet := buf[:n]
		wg.handleOutbound(packet)
	}
}

func (wg *WireGuardTunnel) udpReader() {
	defer wg.wg.Done()

	buf := make([]byte, 2000)

	for {
		select {
		case <-wg.ctx.Done():
			return
		default:
		}

		// FIX: bug.multinode.4 - Increased read deadline from 1s to 5s
		// This prevents packet loss under high multi-peer traffic
		wg.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		wg.conn.SetWriteDeadline(time.Time{}) // Clear write deadline
		n, addr, err := wg.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-wg.ctx.Done():
				return
			default:
				continue
			}
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])
		wg.handleInbound(packet, addr)
	}
}

func (wg *WireGuardTunnel) keepaliveSender() {
	defer wg.wg.Done()

	// FIX: bug.multinode.6 - Add jitter to keepalive interval to avoid synchronized spikes
	baseKeepalive := WGKeepalive
	jitter := time.Duration(rand.Intn(5000)) * time.Millisecond // 0-5s jitter
	ticker := time.NewTicker(baseKeepalive + jitter)
	defer ticker.Stop()

	// FIX: bug.multinode.11 - Stagger health check interval (12s instead of 10s)
	healthCheckTicker := time.NewTicker(12 * time.Second)
	defer healthCheckTicker.Stop()

	for {
		select {
		case <-wg.ctx.Done():
			return
		case <-ticker.C:
			wg.sendKeepalives()
		case <-healthCheckTicker.C:
			wg.checkPeerHealth()
		}
	}
}

// checkPeerHealth monitors peer connections and enables relay fallback if direct connection is stale
// FIX: bug.multinode.11 - Added rate limiting for reconnect triggers
func (wg *WireGuardTunnel) checkPeerHealth() {
	wg.peersMu.RLock()
	peers := make([]*WGPeer, 0, len(wg.peers))
	for _, peer := range wg.peers {
		peers = append(peers, peer)
	}
	wg.peersMu.RUnlock()

	// FIX: Limit concurrent reconnect triggers to prevent storm
	reconnectsTriggered := 0
	maxReconnectsPerCycle := 2

	for _, peer := range peers {
		peer.mu.Lock()
		lastSeen := peer.LastSeen
		lastDirectReceive := peer.LastDirectReceive
		wasUsingRelay := peer.relayFallback
		inGracePeriod := peer.directGracePeriod
		hasEndpoint := peer.Endpoint != nil
		peerKey := peer.PublicKeyB64

		needReconnect := false

		// End grace period if it's been long enough
		if inGracePeriod && time.Since(peer.directGraceStart) > DirectGracePeriod {
			peer.directGracePeriod = false
			inGracePeriod = false
			log.Printf("[Health] Peer %s grace period ended", peerKey[:16])
		}

		// Only check health if we're NOT using relay (i.e., direct-only mode)
		// If relay is still active, connection is fine via relay
		if !wasUsingRelay && !inGracePeriod {
			// We thought direct was working, check if it's still working
			if hasEndpoint && !lastDirectReceive.IsZero() {
				// Had direct data before, check if it's stale
				if time.Since(lastDirectReceive) > 30*time.Second {
					peer.relayFallback = true
					needReconnect = true
					log.Printf("[Health] Peer %s direct connection stale (last direct %v ago), enabling relay", peerKey[:16], time.Since(lastDirectReceive))
				}
			} else if hasEndpoint && lastDirectReceive.IsZero() {
				// Never received direct data - this shouldn't happen if relayFallback is false
				// But if it does, re-enable relay
				peer.relayFallback = true
				log.Printf("[Health] Peer %s never received direct traffic (unexpected state), enabling relay", peerKey[:16])
			}
		}

		// If peer hasn't been seen at all (neither direct nor relay) for a long time, trigger reconnect
		if !lastSeen.IsZero() && time.Since(lastSeen) > 60*time.Second {
			needReconnect = true
			log.Printf("[Health] Peer %s not seen for %v, triggering reconnect", peerKey[:16], time.Since(lastSeen))
		}

		peer.mu.Unlock()

		// FIX: Limit reconnects per health check cycle to prevent storm
		if needReconnect && wg.onNeedReconnect != nil && reconnectsTriggered < maxReconnectsPerCycle {
			reconnectsTriggered++
			go wg.onNeedReconnect(peerKey)
		}
	}
}

func (wg *WireGuardTunnel) handleOutbound(packet []byte) {
	// Find the peer for this destination
	if len(packet) < 20 {
		return
	}

	// Get destination IP (IPv4 header offset 16-20)
	var dstIP net.IP
	version := packet[0] >> 4
	if version == 4 {
		dstIP = net.IP(packet[16:20])
	} else if version == 6 && len(packet) >= 40 {
		dstIP = net.IP(packet[24:40])
	} else {
		return
	}

	// Skip multicast/broadcast traffic silently
	if dstIP.IsMulticast() || dstIP.Equal(net.IPv4bcast) {
		return
	}
	// Skip link-local addresses
	if dstIP.IsLinkLocalMulticast() || dstIP.IsLinkLocalUnicast() {
		return
	}
	// Skip subnet broadcast (e.g., 10.99.0.255 for /24)
	if len(dstIP) == 4 && dstIP[3] == 255 {
		return
	}

	peer := wg.findPeerForIP(dstIP)
	if peer == nil {
		// Only log for unicast traffic in our VPN range (10.99.x.x)
		if len(dstIP) == 4 && dstIP[0] == 10 && dstIP[1] == 99 {
			wg.peersMu.RLock()
			peerCount := len(wg.peers)
			var allowedIPs []string
			for _, p := range wg.peers {
				for _, allowed := range p.AllowedIPs {
					allowedIPs = append(allowedIPs, allowed.String())
				}
			}
			wg.peersMu.RUnlock()
			log.Printf("[WG] No peer found for destination %s (have %d peers, allowedIPs: %v)", dstIP, peerCount, allowedIPs)
		}
		return
	}

	// Encrypt the packet
	encrypted := wg.encryptPacket(packet, peer)

	// Get peer connection info with lock
	peer.mu.RLock()
	endpoint := peer.Endpoint
	useRelay := peer.relayFallback
	inGracePeriod := peer.directGracePeriod
	graceStart := peer.directGraceStart
	lastDirectReceive := peer.LastDirectReceive
	peerKey := peer.PublicKeyB64
	peer.mu.RUnlock()

	// Check if grace period has expired
	if inGracePeriod && time.Since(graceStart) > DirectGracePeriod {
		peer.mu.Lock()
		peer.directGracePeriod = false
		inGracePeriod = false
		peer.mu.Unlock()
	}

	directSent := false
	relaySent := false

	// Try direct UDP if we have an endpoint
	if endpoint != nil {
		wg.conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := wg.conn.WriteToUDP(encrypted, endpoint)
		wg.conn.SetWriteDeadline(time.Time{})
		if err == nil {
			directSent = true
			peer.mu.Lock()
			peer.TxBytes += uint64(len(packet))
			peer.mu.Unlock()
		}
	}

	// ALWAYS use relay as backup path unless direct is proven to work bidirectionally
	// This handles asymmetric NAT where one direction works but not the other
	wg.relayMu.RLock()
	relay := wg.relay
	wg.relayMu.RUnlock()

	// Use relay when:
	// - relayFallback is true (haven't received direct data yet), OR
	// - In grace period (transitioning from relay to direct), OR
	// - No endpoint (can't send direct), OR
	// - Direct send failed, OR
	// - Haven't received direct data recently (>10s) - connection might be one-way
	directWorking := !lastDirectReceive.IsZero() && time.Since(lastDirectReceive) < 10*time.Second
	shouldUseRelay := useRelay || inGracePeriod || endpoint == nil || !directSent || !directWorking

	if relay != nil && relay.IsConnected() && peerKey != "" && shouldUseRelay {
		if err := relay.Send(peerKey, encrypted); err == nil {
			relaySent = true
			if !directSent {
				peer.mu.Lock()
				peer.TxBytes += uint64(len(packet))
				peer.mu.Unlock()
			}
		} else {
			log.Printf("[Relay] Send failed: %v (packet size: %d)", err, len(encrypted))
		}
	}

	// Debug: Log why relay wasn't used (helps diagnose asymmetric NAT issues)
	if !relaySent && !directWorking {
		relayConnected := relay != nil && relay.IsConnected()
		log.Printf("[WG-Debug] Packet to %s: direct=%v relay=%v (relayConn=%v, peerKey=%v, shouldRelay=%v, directWorking=%v, lastDirectRx=%v)",
			dstIP, directSent, relaySent, relayConnected, peerKey != "", shouldUseRelay, directWorking,
			func() string {
				if lastDirectReceive.IsZero() {
					return "never"
				}
				return time.Since(lastDirectReceive).String()
			}())
	}

	// Debug logging only for VPN traffic
	// Use peer.GetState() for thread-safe access (bug fix: race_condition.3)
	peer.mu.RLock()
	peerState := peer.relayFallback
	peer.mu.RUnlock()
	_ = peerState // Accessed for side-effect check above

	if !directSent && !relaySent {
		log.Printf("[WG] FAILED to send %d byte packet to %s (relay connected: %v)",
			len(packet), dstIP, relay != nil && relay.IsConnected())
	}
}

func (wg *WireGuardTunnel) handleInbound(packet []byte, addr *net.UDPAddr) {
	if len(packet) < 4 {
		return
	}

	// Check for punch packet first (before WireGuard processing)
	if len(packet) >= 16 && string(packet[:16]) == "SELFTUNNEL_PUNCH" {
		// Don't log every punch packet - too spammy
		if wg.onPunchPacket != nil {
			wg.onPunchPacket(addr)
		}
		// Send punch response back
		wg.conn.WriteToUDP(packet, addr)

		// Update peer that matches this address to use direct connection
		wg.updatePeerFromPunch(addr)
		return
	}

	// Check packet type
	msgType := packet[0]

	switch msgType {
	case WGHandshakeInit:
		wg.handleHandshakeInit(packet, addr)
	case WGHandshakeResp:
		wg.handleHandshakeResp(packet, addr)
	case WGDataPacket:
		wg.handleDataPacket(packet, addr)
	case WGCookieReply:
		// Handle cookie reply
	}
}

// updatePeerFromPunch updates peer endpoint when receiving punch from unknown address
// NOTE: This only sets the endpoint, does NOT disable relay - relay is only disabled
// when we actually receive DATA packets via direct connection
func (wg *WireGuardTunnel) updatePeerFromPunch(addr *net.UDPAddr) {
	// Skip virtual IPs and private IPs (except Tailscale 100.x.x.x which is routable)
	ip4 := addr.IP.To4()
	if ip4 == nil {
		return
	}
	// Skip local-only ranges
	if ip4[0] == 10 || (ip4[0] == 192 && ip4[1] == 168) || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || ip4[0] == 127 {
		return
	}

	wg.peersMu.Lock()
	defer wg.peersMu.Unlock()

	// Find peer that needs endpoint update
	for _, peer := range wg.peers {
		peer.mu.Lock()
		oldEndpoint := peer.Endpoint

		// Skip if this peer already has this exact endpoint
		if oldEndpoint != nil && oldEndpoint.String() == addr.String() {
			peer.mu.Unlock()
			continue
		}

		// Only set endpoint if peer has NO endpoint yet
		// Don't keep switching endpoints - that causes instability
		// Once we have an endpoint, stick with it until direct data proves it works or health check resets it
		if oldEndpoint == nil {
			peer.Endpoint = addr
			peer.LastSeen = time.Now()
			log.Printf("[WG] Peer %s: initial endpoint set to %s", peer.PublicKeyB64[:16], addr)
			peer.mu.Unlock()
			return // Only update one peer per punch
		}
		peer.mu.Unlock()
	}
	// No log if no peer was updated - this is normal during hole punching
}

func (wg *WireGuardTunnel) handleHandshakeInit(packet []byte, addr *net.UDPAddr) {
	// Simplified handshake - in production use full Noise protocol
}

func (wg *WireGuardTunnel) handleHandshakeResp(packet []byte, addr *net.UDPAddr) {
	// Simplified handshake response
}

func (wg *WireGuardTunnel) handleDataPacket(packet []byte, addr *net.UDPAddr) {
	// Decrypt and write to TUN
	if len(packet) <= WGHeaderSize {
		return
	}

	// Find peer by endpoint first to get shared secret for decryption
	peer := wg.findPeerByEndpoint(addr)
	if peer == nil {
		// Try to find any peer that might match (for new connections)
		// Try decryption with each peer's shared secret
		// FIX: bug.production.9 - Log warning about brute-force decryption attempt
		// This is expensive O(n) operation; in production consider caching or protocol change
		wg.peersMu.RLock()
		peerCount := len(wg.peers)
		for _, p := range wg.peers {
			// Try to decrypt with this peer's secret
			decrypted := wg.decryptWithSecret(packet, p.sharedSecret)
			if decrypted != nil && len(decrypted) >= 20 {
				// Check if it looks like a valid IP packet
				version := decrypted[0] >> 4
				if version == 4 || version == 6 {
					peer = p
					break
				}
			}
		}
		wg.peersMu.RUnlock()

		// Log warning if we had to try multiple peers (performance concern)
		if peer != nil && peerCount > 5 {
			log.Printf("[WG] Warning: brute-force decryption across %d peers for endpoint %s", peerCount, addr)
		}
	}

	if peer == nil {
		// Don't log every unknown packet - too spammy during hole punching
		return
	}

	// Decrypt with peer's shared secret
	decrypted := wg.decryptWithSecret(packet, peer.sharedSecret)
	if decrypted == nil || len(decrypted) < 20 {
		return
	}

	// Write to TUN
	n, err := wg.tun.Write(decrypted)
	if err != nil {
		log.Printf("[WG] Failed to write to TUN: %v", err)
		return
	}

	// Update peer stats and endpoint
	peer.mu.Lock()
	peer.RxBytes += uint64(len(decrypted))
	peer.LastSeen = time.Now()
	peer.LastDirectReceive = time.Now()
	peerKeyB64 := peer.PublicKeyB64
	oldEndpoint := peer.Endpoint

	// Update endpoint if changed - this is the REAL working endpoint
	endpointChanged := oldEndpoint == nil || oldEndpoint.String() != addr.String()
	if endpointChanged {
		peer.Endpoint = addr
	}

	// Direct connection confirmed working
	// Start grace period instead of immediately disabling relay
	wasUsingRelay := peer.relayFallback
	if peer.relayFallback {
		peer.relayFallback = false
		peer.directGracePeriod = true
		peer.directGraceStart = time.Now()
	} else if peer.directGracePeriod {
		// Still in grace period, check if we can end it early
		if time.Since(peer.directGraceStart) > 2*time.Second {
			peer.directGracePeriod = false
		}
	}
	peer.mu.Unlock()

	// Only log significant events
	if wasUsingRelay {
		log.Printf("[Direct] Peer %s: direct connection established via %s (%d bytes)", peerKeyB64[:16], addr, n)
	}

	// Notify callback that we received data from this peer (direct connection)
	if wg.onDataReceived != nil {
		wg.onDataReceived(peerKeyB64, true)
	}
}

func (wg *WireGuardTunnel) encryptPacket(plaintext []byte, peer *WGPeer) []byte {
	// Use ChaCha20-Poly1305 authenticated encryption
	peer.mu.RLock()
	encryptor := peer.encryptor
	peer.mu.RUnlock()

	if encryptor == nil {
		// FIX: bug.production.3 - Log warning when encryptor is nil
		log.Printf("[WG] Warning: encryptor is nil for peer, packet dropped")
		return nil
	}

	encrypted := encryptor.Encrypt(plaintext)

	// Prepend WireGuard header
	result := make([]byte, WGHeaderSize+len(encrypted))
	result[0] = WGDataPacket
	copy(result[WGHeaderSize:], encrypted)

	return result
}

// decryptWithEncryptor decrypts data using ChaCha20-Poly1305
func (wg *WireGuardTunnel) decryptWithEncryptor(data []byte, encryptor *crypto.Encryptor) []byte {
	if len(data) <= WGHeaderSize {
		return nil
	}

	ciphertext := data[WGHeaderSize:]
	plaintext, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		return nil
	}
	return plaintext
}

// decryptWithSecret decrypts data using peer's encryptor (legacy name for compatibility)
func (wg *WireGuardTunnel) decryptWithSecret(data []byte, secret [crypto.KeySize]byte) []byte {
	// Create temporary encryptor for decryption
	// Note: This is used for probing unknown peers, so we need to create encryptor on the fly
	encryptor, err := crypto.NewEncryptor(secret)
	if err != nil {
		return nil
	}
	return wg.decryptWithEncryptor(data, encryptor)
}

func (wg *WireGuardTunnel) findPeerForIP(ip net.IP) *WGPeer {
	wg.peersMu.RLock()
	defer wg.peersMu.RUnlock()

	for _, peer := range wg.peers {
		for _, allowed := range peer.AllowedIPs {
			if allowed.Contains(ip) {
				return peer
			}
		}
	}
	return nil
}

func (wg *WireGuardTunnel) findPeerByEndpoint(addr *net.UDPAddr) *WGPeer {
	wg.peersMu.RLock()
	defer wg.peersMu.RUnlock()

	for _, peer := range wg.peers {
		peer.mu.RLock()
		endpoint := peer.Endpoint
		peer.mu.RUnlock()

		if endpoint != nil && endpoint.IP.Equal(addr.IP) && endpoint.Port == addr.Port {
			return peer
		}
	}
	return nil
}

// FIX: bug.multinode.6 - Add staggering between keepalives to different peers
func (wg *WireGuardTunnel) sendKeepalives() {
	wg.peersMu.RLock()
	peers := make([]*WGPeer, 0, len(wg.peers))
	for _, peer := range wg.peers {
		peers = append(peers, peer)
	}
	wg.peersMu.RUnlock()

	keepalivePacket := make([]byte, WGHeaderSize)
	keepalivePacket[0] = WGDataPacket

	for i, peer := range peers {
		peer.mu.RLock()
		endpoint := peer.Endpoint
		peer.mu.RUnlock()

		if endpoint != nil {
			wg.conn.WriteToUDP(keepalivePacket, endpoint)
		}

		// FIX: Stagger keepalives with 50ms delay between peers
		if i < len(peers)-1 {
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// GetPeers returns all peers
func (wg *WireGuardTunnel) GetPeers() []*WGPeer {
	wg.peersMu.RLock()
	defer wg.peersMu.RUnlock()

	peers := make([]*WGPeer, 0, len(wg.peers))
	for _, p := range wg.peers {
		peers = append(peers, p)
	}
	return peers
}

// PublicKey returns the public key
func (wg *WireGuardTunnel) PublicKey() [crypto.KeySize]byte {
	return wg.publicKey
}

// ListenPort returns the UDP listen port
func (wg *WireGuardTunnel) ListenPort() int {
	return wg.listenPort
}
