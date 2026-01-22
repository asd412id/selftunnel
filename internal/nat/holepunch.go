package nat

import (
	"context"
	"fmt"
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
	// Create UDP listener on random port
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP listener: %w", err)
	}

	return &HolePuncher{
		localConn:  conn,
		stunClient: NewSTUNClient(stunServers),
	}, nil
}

func NewHolePuncherWithPort(stunServers []string, port int) (*HolePuncher, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP listener on port %d: %w", port, err)
	}

	return &HolePuncher{
		localConn:  conn,
		stunClient: NewSTUNClient(stunServers),
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
func (hp *HolePuncher) SimultaneousPunch(ctx context.Context, peerEndpoints []string, duration time.Duration) (*net.UDPAddr, error) {
	deadline := time.Now().Add(duration)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	punchPacket := []byte("SELFTUNNEL_PUNCH")

	// Resolve all peer addresses
	var peerAddrs []*net.UDPAddr
	for _, endpoint := range peerEndpoints {
		addr, err := net.ResolveUDPAddr("udp", endpoint)
		if err == nil {
			peerAddrs = append(peerAddrs, addr)
		}
	}

	if len(peerAddrs) == 0 {
		return nil, fmt.Errorf("no valid peer endpoints")
	}

	// Start sender goroutine
	done := make(chan *net.UDPAddr, 1)
	errCh := make(chan error, 1)

	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, addr := range peerAddrs {
					hp.localConn.WriteToUDP(punchPacket, addr)
				}
			}
		}
	}()

	// Receiver
	go func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}

			hp.localConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := hp.localConn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				continue
			}

			// Check if it's a punch packet from one of our peers
			if n >= len(punchPacket) && string(buf[:len(punchPacket)]) == string(punchPacket) {
				for _, peerAddr := range peerAddrs {
					if addr.IP.Equal(peerAddr.IP) {
						done <- addr
						return
					}
				}
			}
		}
	}()

	select {
	case addr := <-done:
		return addr, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
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
