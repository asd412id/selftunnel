package nat

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

type HolePuncher struct {
	localConn   *net.UDPConn
	stunClient  *STUNClient
	mappedAddr  *MappedAddress
	natType     NATType
	natDetected bool // Flag to prevent multiple NAT detection goroutines
	mu          sync.RWMutex
}

type PunchResult struct {
	LocalAddr  *net.UDPAddr
	MappedAddr *MappedAddress
	Success    bool
	Error      error
}

func NewHolePuncher(stunServers []string) (*HolePuncher, error) {
	// Create UDP listener on random port - use udp4 for IPv4 only
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP listener: %w", err)
	}

	stunClient := NewSTUNClient(stunServers)
	stunClient.SetConn(conn) // Use shared connection

	return &HolePuncher{
		localConn:  conn,
		stunClient: stunClient,
	}, nil
}

func NewHolePuncherWithPort(stunServers []string, port int) (*HolePuncher, error) {
	// Use udp4 for IPv4 only to avoid issues with IPv6 binding on Windows
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP listener on port %d: %w", port, err)
	}

	stunClient := NewSTUNClient(stunServers)
	stunClient.SetConn(conn) // Use shared connection

	return &HolePuncher{
		localConn:  conn,
		stunClient: stunClient,
	}, nil
}

// DiscoverPublicAddr uses STUN to discover the public address and detect NAT type
func (hp *HolePuncher) DiscoverPublicAddr() (*MappedAddress, error) {
	localAddr := hp.localConn.LocalAddr().(*net.UDPAddr)

	// First get mapped address
	mapped, err := hp.stunClient.GetMappedAddress(localAddr)
	if err != nil {
		return nil, err
	}

	hp.mu.Lock()
	hp.mappedAddr = mapped
	alreadyDetecting := hp.natDetected
	hp.natDetected = true
	hp.mu.Unlock()

	// Detect NAT type in background (only once)
	if !alreadyDetecting {
		go func() {
			// Use timeout to prevent hanging
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			done := make(chan struct{})
			var natType NATType
			var detectErr error

			go func() {
				natType, detectErr = hp.stunClient.DetectNATType(localAddr)
				close(done)
			}()

			select {
			case <-ctx.Done():
				log.Printf("[NAT] NAT type detection timed out")
				return
			case <-done:
				if detectErr != nil {
					log.Printf("[NAT] Could not detect NAT type: %v", detectErr)
					return
				}
				hp.mu.Lock()
				hp.natType = natType
				hp.mu.Unlock()
				log.Printf("[NAT] Detected NAT type: %s", natType)
			}
		}()
	}

	return mapped, nil
}

// GetNATType returns the detected NAT type
func (hp *HolePuncher) GetNATType() NATType {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.natType
}

// GetMappedAddr returns the discovered public address
func (hp *HolePuncher) GetMappedAddr() *MappedAddress {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.mappedAddr
}

// LocalAddr returns the local UDP address
func (hp *HolePuncher) LocalAddr() *net.UDPAddr {
	return hp.localConn.LocalAddr().(*net.UDPAddr)
}

// Conn returns the underlying UDP connection
func (hp *HolePuncher) Conn() *net.UDPConn {
	return hp.localConn
}

// PunchHole attempts to establish a connection with a peer through NAT
func (hp *HolePuncher) PunchHole(ctx context.Context, peerEndpoints []string) (*net.UDPAddr, error) {
	// Try each endpoint
	for _, endpoint := range peerEndpoints {
		peerAddr, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			continue
		}

		// Send multiple punch packets
		success, err := hp.attemptPunch(ctx, peerAddr)
		if err == nil && success {
			return peerAddr, nil
		}
	}

	return nil, fmt.Errorf("failed to punch hole to any endpoint")
}

func (hp *HolePuncher) attemptPunch(ctx context.Context, peerAddr *net.UDPAddr) (bool, error) {
	// Send punch packets
	punchPacket := []byte("SELFTUNNEL_PUNCH")

	for i := 0; i < 5; i++ {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}

		_, err := hp.localConn.WriteToUDP(punchPacket, peerAddr)
		if err != nil {
			return false, err
		}

		time.Sleep(100 * time.Millisecond)
	}

	// Wait for response
	hp.localConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}

		n, addr, err := hp.localConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return false, nil
			}
			return false, err
		}

		// Check if it's from our target peer
		if addr.IP.Equal(peerAddr.IP) && addr.Port == peerAddr.Port {
			if n >= len(punchPacket) && string(buf[:len(punchPacket)]) == string(punchPacket) {
				return true, nil
			}
		}
	}
}

// SimultaneousPunch performs simultaneous open with a peer
// Uses birthday attack for symmetric NAT traversal
func (hp *HolePuncher) SimultaneousPunch(ctx context.Context, peerEndpoints []string, duration time.Duration) (*net.UDPAddr, error) {
	deadline := time.Now().Add(duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	punchPacket := []byte("SELFTUNNEL_PUNCH")

	// Resolve all peer addresses
	var peerAddrs []*net.UDPAddr
	seenAddrs := make(map[string]bool)

	for _, endpoint := range peerEndpoints {
		addr, err := net.ResolveUDPAddr("udp", endpoint)
		if err == nil {
			key := addr.String()
			if !seenAddrs[key] {
				seenAddrs[key] = true
				peerAddrs = append(peerAddrs, addr)
			}
		}
	}

	// Get NAT info for smarter port prediction
	hp.mu.RLock()
	natType := hp.natType
	portDelta := hp.stunClient.GetPortDelta()
	hp.mu.RUnlock()

	// Generate predicted ports based on NAT type
	var predictedAddrs []*net.UDPAddr

	for _, addr := range peerAddrs {
		if !isPublicIPAddr(addr.IP) {
			continue
		}

		if natType == NATTypeSymmetric {
			// For symmetric NAT: use birthday attack with wider range
			// Also use port delta if detected
			predictedAddrs = append(predictedAddrs, generateSymmetricNATPorts(addr, portDelta, seenAddrs)...)
		} else {
			// For cone NAT: use smaller range around known port
			for offset := -10; offset <= 10; offset++ {
				if offset == 0 {
					continue
				}
				predictedPort := addr.Port + offset
				if predictedPort > 0 && predictedPort < 65536 {
					predicted := &net.UDPAddr{IP: addr.IP, Port: predictedPort}
					key := predicted.String()
					if !seenAddrs[key] {
						seenAddrs[key] = true
						predictedAddrs = append(predictedAddrs, predicted)
					}
				}
			}
		}
	}

	allAddrs := append(peerAddrs, predictedAddrs...)
	log.Printf("[HolePunch] Punching to %d endpoints (%d original + %d predicted, NAT: %s)",
		len(allAddrs), len(peerAddrs), len(predictedAddrs), natType)

	if len(allAddrs) == 0 {
		return nil, fmt.Errorf("no valid peer endpoints")
	}

	// Send punch packets at high rate for birthday attack
	// For symmetric NAT, we need to hit the right port combination
	ticker := time.NewTicker(10 * time.Millisecond) // Faster for birthday attack
	defer ticker.Stop()

	packetsSent := 0
	batchSize := 50 // Send to multiple addresses per tick

	for {
		select {
		case <-ctx.Done():
			log.Printf("[HolePunch] Punch complete: sent %d packets to %d endpoints", packetsSent, len(allAddrs))
			// Return first public endpoint as expected - actual endpoint will be set by WireGuard callback
			for _, addr := range peerAddrs {
				if isPublicIPAddr(addr.IP) {
					return addr, nil
				}
			}
			if len(peerAddrs) > 0 {
				return peerAddrs[0], nil
			}
			return nil, fmt.Errorf("punch timeout")
		case <-ticker.C:
			// Send to a batch of addresses
			for i := 0; i < batchSize && i < len(allAddrs); i++ {
				idx := (packetsSent + i) % len(allAddrs)
				hp.localConn.WriteToUDP(punchPacket, allAddrs[idx])
			}
			packetsSent += batchSize
		}
	}
}

// generateSymmetricNATPorts generates port predictions for symmetric NAT using birthday attack
func generateSymmetricNATPorts(addr *net.UDPAddr, portDelta int, seen map[string]bool) []*net.UDPAddr {
	var addrs []*net.UDPAddr
	basePort := addr.Port

	// Strategy 1: Sequential ports around base (±100)
	for offset := -100; offset <= 100; offset++ {
		if offset == 0 {
			continue
		}
		port := basePort + offset
		if port > 1024 && port < 65535 {
			predicted := &net.UDPAddr{IP: addr.IP, Port: port}
			key := predicted.String()
			if !seen[key] {
				seen[key] = true
				addrs = append(addrs, predicted)
			}
		}
	}

	// Strategy 2: Use detected port delta if available
	if portDelta != 0 && portDelta > 0 && portDelta < 100 {
		for i := 1; i <= 50; i++ {
			port := basePort + (portDelta * i)
			if port > 1024 && port < 65535 {
				predicted := &net.UDPAddr{IP: addr.IP, Port: port}
				key := predicted.String()
				if !seen[key] {
					seen[key] = true
					addrs = append(addrs, predicted)
				}
			}
		}
	}

	// Strategy 3: Birthday attack - random ports in ephemeral range
	// For symmetric NAT, both sides use random ports, so we try many combinations
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 200; i++ {
		// Focus on ephemeral port range (32768-65535) where most NATs allocate
		port := 32768 + rng.Intn(32767)
		predicted := &net.UDPAddr{IP: addr.IP, Port: port}
		key := predicted.String()
		if !seen[key] {
			seen[key] = true
			addrs = append(addrs, predicted)
		}
	}

	return addrs
}

// Close closes the hole puncher
func (hp *HolePuncher) Close() error {
	return hp.localConn.Close()
}

// GetEndpoints returns all known endpoints (local + mapped)
func (hp *HolePuncher) GetEndpoints() []string {
	endpoints := []string{}

	localAddr := hp.localConn.LocalAddr().(*net.UDPAddr)

	// Add local addresses
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					endpoints = append(endpoints, fmt.Sprintf("%s:%d", ipNet.IP, localAddr.Port))
				}
			}
		}
	}

	// Add mapped address
	hp.mu.RLock()
	if hp.mappedAddr != nil {
		endpoints = append(endpoints, fmt.Sprintf("%s:%d", hp.mappedAddr.IP, hp.mappedAddr.Port))
	}
	hp.mu.RUnlock()

	return endpoints
}

// isPublicIPAddr checks if an IP is a public/routable IP
func isPublicIPAddr(ip net.IP) bool {
	if ip == nil {
		return false
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	// Private/special ranges
	if ip4[0] == 10 ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168) ||
		(ip4[0] == 169 && ip4[1] == 254) ||
		ip4[0] == 127 {
		return false
	}

	return true
}
