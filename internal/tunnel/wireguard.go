package tunnel

import (
	"context"
	"fmt"
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

type WireGuardTunnel struct {
	tun        *TUNDevice
	privateKey [crypto.KeySize]byte
	publicKey  [crypto.KeySize]byte
	listenPort int
	conn       *net.UDPConn
	peers      map[string]*WGPeer
	peersMu    sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

type WGPeer struct {
	PublicKey    [crypto.KeySize]byte
	Endpoint     *net.UDPAddr
	AllowedIPs   []*net.IPNet
	LastSeen     time.Time
	TxBytes      uint64
	RxBytes      uint64
	Keepalive    time.Duration
	sharedSecret [crypto.KeySize]byte
	mu           sync.RWMutex
}

type WireGuardConfig struct {
	TUN        *TUNDevice
	PrivateKey [crypto.KeySize]byte
	ListenPort int
}

func NewWireGuardTunnel(cfg WireGuardConfig) (*WireGuardTunnel, error) {
	publicKey := crypto.PublicKeyFromPrivate(cfg.PrivateKey)

	addr := &net.UDPAddr{Port: cfg.ListenPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP port %d: %w", cfg.ListenPort, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	wg := &WireGuardTunnel{
		tun:        cfg.TUN,
		privateKey: cfg.PrivateKey,
		publicKey:  publicKey,
		listenPort: cfg.ListenPort,
		conn:       conn,
		peers:      make(map[string]*WGPeer),
		ctx:        ctx,
		cancel:     cancel,
	}

	return wg, nil
}

// AddPeer adds a new peer to the tunnel
func (wg *WireGuardTunnel) AddPeer(publicKey [crypto.KeySize]byte, endpoint string, allowedIPs []string) error {
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

	peer := &WGPeer{
		PublicKey:    publicKey,
		Endpoint:     endpointAddr,
		AllowedIPs:   allowed,
		Keepalive:    WGKeepalive,
		sharedSecret: sharedSecret,
	}

	key := crypto.ToBase64(publicKey)

	wg.peersMu.Lock()
	wg.peers[key] = peer
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

// UpdatePeerEndpoint updates a peer's endpoint
func (wg *WireGuardTunnel) UpdatePeerEndpoint(publicKey [crypto.KeySize]byte, endpoint string) error {
	key := crypto.ToBase64(publicKey)

	endpointAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("failed to resolve endpoint: %w", err)
	}

	wg.peersMu.Lock()
	if peer, ok := wg.peers[key]; ok {
		peer.mu.Lock()
		peer.Endpoint = endpointAddr
		peer.mu.Unlock()
	}
	wg.peersMu.Unlock()

	return nil
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
	wg.conn.Close()
	wg.tun.Close()
	wg.wg.Wait()
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

		wg.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
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

	for {
		select {
		case <-wg.ctx.Done():
			return
		case <-ticker.C:
			wg.sendKeepalives()
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

	peer := wg.findPeerForIP(dstIP)
	if peer == nil {
		return
	}

	peer.mu.RLock()
	endpoint := peer.Endpoint
	peer.mu.RUnlock()

	if endpoint == nil {
		return
	}

	// In a real implementation, we would encrypt the packet here
	// For now, we send it with a simple header
	encrypted := wg.encryptPacket(packet, peer)

	wg.conn.WriteToUDP(encrypted, endpoint)

	peer.mu.Lock()
	peer.TxBytes += uint64(len(packet))
	peer.mu.Unlock()
}

func (wg *WireGuardTunnel) handleInbound(packet []byte, addr *net.UDPAddr) {
	if len(packet) < 4 {
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

	decrypted := wg.decryptPacket(packet)
	if decrypted == nil {
		return
	}

	wg.tun.Write(decrypted)

	// Update peer stats
	peer := wg.findPeerByEndpoint(addr)
	if peer != nil {
		peer.mu.Lock()
		peer.RxBytes += uint64(len(decrypted))
		peer.LastSeen = time.Now()
		peer.mu.Unlock()
	}
}

func (wg *WireGuardTunnel) encryptPacket(plaintext []byte, peer *WGPeer) []byte {
	// Simplified encryption - in production use ChaCha20-Poly1305
	// This is a placeholder that just prepends a header
	result := make([]byte, WGHeaderSize+len(plaintext))
	result[0] = WGDataPacket
	copy(result[WGHeaderSize:], plaintext)
	return result
}

func (wg *WireGuardTunnel) decryptPacket(ciphertext []byte) []byte {
	// Simplified decryption - in production use ChaCha20-Poly1305
	if len(ciphertext) <= WGHeaderSize {
		return nil
	}
	return ciphertext[WGHeaderSize:]
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
