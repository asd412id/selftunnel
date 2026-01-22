package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/selftunnel/selftunnel/internal/crypto"
)

const (
	WGHeaderSize    = 16
	WGKeepalive     = 25 * time.Second
	WGHandshakeInit = 1
	WGHandshakeResp = 2
	WGDataPacket    = 4
	WGCookieReply   = 3
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
	PublicKey     [crypto.KeySize]byte
	PublicKeyB64  string // base64 encoded public key for relay lookup
	Endpoint      *net.UDPAddr
	AllowedIPs    []*net.IPNet
	LastSeen      time.Time
	TxBytes       uint64
	RxBytes       uint64
	Keepalive     time.Duration
	sharedSecret  [crypto.KeySize]byte
	relayFallback bool // true if using relay instead of direct UDP
	mu            sync.RWMutex
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

		// Only set read deadline, not affecting write
		wg.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
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

	ticker := time.NewTicker(WGKeepalive)
	defer ticker.Stop()

	healthCheckTicker := time.NewTicker(10 * time.Second)
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
func (wg *WireGuardTunnel) checkPeerHealth() {
	wg.peersMu.RLock()
	defer wg.peersMu.RUnlock()

	for _, peer := range wg.peers {
		peer.mu.Lock()
		lastSeen := peer.LastSeen
		wasUsingRelay := peer.relayFallback
		hasEndpoint := peer.Endpoint != nil
		peerKey := peer.PublicKeyB64

		needReconnect := false

		// If we have a direct endpoint but haven't received data in 15+ seconds,
		// enable relay fallback (connection might be broken)
		// Reduced from 30s to 15s for faster recovery on IP changes
		if hasEndpoint && !wasUsingRelay && !lastSeen.IsZero() {
			if time.Since(lastSeen) > 15*time.Second {
				peer.relayFallback = true
				needReconnect = true
				log.Printf("[Health] Peer %s direct connection stale (last seen %v ago), enabling relay fallback", peerKey[:16], time.Since(lastSeen))
			}
		}

		peer.mu.Unlock()

		// Trigger reconnection attempt outside of lock
		if needReconnect && wg.onNeedReconnect != nil {
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
	peerKey := peer.PublicKeyB64
	peer.mu.RUnlock()

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

	// ALWAYS use relay as backup when:
	// - relayFallback is true (direct not yet proven), OR
	// - No endpoint available, OR
	// - Direct send failed
	wg.relayMu.RLock()
	relay := wg.relay
	wg.relayMu.RUnlock()

	if relay != nil && relay.IsConnected() && peerKey != "" {
		// Use relay if: no direct endpoint, direct failed, or relay mode is active
		if endpoint == nil || !directSent || useRelay {
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
	}

	// Debug logging only for VPN traffic
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
func (wg *WireGuardTunnel) updatePeerFromPunch(addr *net.UDPAddr) {
	// Skip virtual IPs and private IPs
	ip4 := addr.IP.To4()
	if ip4 == nil {
		return
	}
	if ip4[0] == 10 || (ip4[0] == 192 && ip4[1] == 168) || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || ip4[0] == 127 {
		return
	}

	wg.peersMu.Lock()
	defer wg.peersMu.Unlock()

	for _, peer := range wg.peers {
		peer.mu.Lock()
		// Update if peer has no endpoint, is using relay, or endpoint doesn't match
		needUpdate := peer.Endpoint == nil || peer.relayFallback
		if needUpdate {
			oldEndpoint := peer.Endpoint
			peer.Endpoint = addr
			peer.relayFallback = false
			peer.LastSeen = time.Now()
			if oldEndpoint == nil {
				log.Printf("[WG] Peer %s: endpoint set to %s (direct ENABLED)", peer.PublicKeyB64[:16], addr)
			} else {
				log.Printf("[WG] Peer %s: endpoint %s -> %s (direct ENABLED)", peer.PublicKeyB64[:16], oldEndpoint, addr)
			}
		} else if peer.Endpoint != nil && peer.Endpoint.String() != addr.String() {
			// Different endpoint - NAT rebinding, update silently
			peer.Endpoint = addr
			peer.LastSeen = time.Now()
		}
		peer.mu.Unlock()
	}
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
		wg.peersMu.RLock()
		for _, p := range wg.peers {
			p.mu.RLock()
			// Accept from any peer that is using relay or has no endpoint
			if p.relayFallback || p.Endpoint == nil {
				peer = p
				p.mu.RUnlock()
				break
			}
			p.mu.RUnlock()
		}
		wg.peersMu.RUnlock()
	}

	if peer == nil {
		log.Printf("[WG] Received data from unknown endpoint %s, no matching peer", addr)
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
	peerKeyB64 := peer.PublicKeyB64

	// Update endpoint if changed
	if peer.Endpoint == nil || peer.Endpoint.String() != addr.String() {
		peer.Endpoint = addr
	}

	// Direct connection confirmed working - disable relay fallback
	if peer.relayFallback {
		peer.relayFallback = false
		log.Printf("[Direct] Data received from %s (%d bytes), relay DISABLED", addr, n)
	}
	peer.mu.Unlock()

	// Notify callback that we received data from this peer (direct connection)
	if wg.onDataReceived != nil {
		wg.onDataReceived(peerKeyB64, true)
	}
}

func (wg *WireGuardTunnel) encryptPacket(plaintext []byte, peer *WGPeer) []byte {
	// XOR encryption with shared secret
	result := make([]byte, WGHeaderSize+len(plaintext))
	result[0] = WGDataPacket

	// XOR plaintext with shared secret
	for i := 0; i < len(plaintext); i++ {
		result[WGHeaderSize+i] = plaintext[i] ^ peer.sharedSecret[i%len(peer.sharedSecret)]
	}
	return result
}

// decryptWithSecret decrypts data using XOR with shared secret
func (wg *WireGuardTunnel) decryptWithSecret(data []byte, secret [crypto.KeySize]byte) []byte {
	if len(data) <= WGHeaderSize {
		return nil
	}

	ciphertext := data[WGHeaderSize:]
	plaintext := make([]byte, len(ciphertext))

	// XOR ciphertext with shared secret
	for i := 0; i < len(ciphertext); i++ {
		plaintext[i] = ciphertext[i] ^ secret[i%len(secret)]
	}
	return plaintext
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

func (wg *WireGuardTunnel) sendKeepalives() {
	wg.peersMu.RLock()
	defer wg.peersMu.RUnlock()

	keepalivePacket := make([]byte, WGHeaderSize)
	keepalivePacket[0] = WGDataPacket

	for _, peer := range wg.peers {
		peer.mu.RLock()
		endpoint := peer.Endpoint
		peer.mu.RUnlock()

		if endpoint != nil {
			wg.conn.WriteToUDP(keepalivePacket, endpoint)
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
