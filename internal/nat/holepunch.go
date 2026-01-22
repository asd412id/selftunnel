package nat

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type HolePuncher struct {
	localConn  *net.UDPConn
	stunClient *STUNClient
	mappedAddr *MappedAddress
	mu         sync.RWMutex
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

// DiscoverPublicAddr uses STUN to discover the public address
func (hp *HolePuncher) DiscoverPublicAddr() (*MappedAddress, error) {
	localAddr := hp.localConn.LocalAddr().(*net.UDPAddr)

	mapped, err := hp.stunClient.GetMappedAddress(localAddr)
	if err != nil {
		return nil, err
	}

	hp.mu.Lock()
	hp.mappedAddr = mapped
	hp.mu.Unlock()

	return mapped, nil
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
// Returns the peer's actual address from which we received punch packets
// NOTE: Since UDP connection is shared with WireGuard, punch packets may be received
// by WireGuard instead of this receiver. The WireGuard handler should call back
// to update peer endpoints when it receives punch packets.
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

	// Add port predictions for symmetric NAT traversal
	var predictedAddrs []*net.UDPAddr
	for _, addr := range peerAddrs {
		if isPublicIPAddr(addr.IP) {
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
	log.Printf("[HolePunch] Punching to %d endpoints (%d original + %d predicted)", len(allAddrs), len(peerAddrs), len(predictedAddrs))

	if len(allAddrs) == 0 {
		return nil, fmt.Errorf("no valid peer endpoints")
	}

	// Just send punch packets - don't try to receive here since WireGuard will handle incoming
	// Send for the full duration to give peer time to respond
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	packetsSent := 0
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
			for _, addr := range allAddrs {
				hp.localConn.WriteToUDP(punchPacket, addr)
				packetsSent++
			}
		}
	}
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
