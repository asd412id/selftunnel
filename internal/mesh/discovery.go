package mesh

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/selftunnel/selftunnel/internal/nat"
	"github.com/selftunnel/selftunnel/internal/relay"
)

type Discovery struct {
	peerManager   *PeerManager
	holePuncher   *nat.HolePuncher
	relayClient   *relay.Client
	onDiscovered  func(*Peer, *nat.MappedAddress)
	onPeerConnect func(publicKey string, endpoint string) // callback when direct connection established
	punchCooldown map[string]time.Time                    // track last punch attempt per peer
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

func NewDiscovery(pm *PeerManager, hp *nat.HolePuncher) *Discovery {
	ctx, cancel := context.WithCancel(context.Background())

	return &Discovery{
		peerManager:   pm,
		holePuncher:   hp,
		punchCooldown: make(map[string]time.Time),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// SetDiscoveryCallback sets the callback for when a peer is discovered
func (d *Discovery) SetDiscoveryCallback(callback func(*Peer, *nat.MappedAddress)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onDiscovered = callback
}

// SetPeerConnectCallback sets the callback for when direct connection is established
func (d *Discovery) SetPeerConnectCallback(callback func(publicKey string, endpoint string)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onPeerConnect = callback
}

// SetRelayClient sets the relay client for punch coordination
func (d *Discovery) SetRelayClient(client *relay.Client) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.relayClient = client
}

// Start starts the discovery process
func (d *Discovery) Start() error {
	// Discover our public address first
	mapped, err := d.holePuncher.DiscoverPublicAddr()
	if err != nil {
		// Not fatal - we might be on a local network
		mapped = nil
	}

	// Update local peer's endpoints (with nil check for safety - bug fix: nil_pointer.2)
	localPeer := d.peerManager.LocalPeer()
	if localPeer != nil {
		localPeer.mu.Lock()
		localPeer.Endpoints = d.holePuncher.GetEndpoints()
		localPeer.mu.Unlock()
	}

	// Start periodic discovery
	d.wg.Add(1)
	go d.discoveryLoop()

	// Start connection maintenance
	d.wg.Add(1)
	go d.maintenanceLoop()

	_ = mapped
	return nil
}

func (d *Discovery) discoveryLoop() {
	defer d.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.refreshPublicAddress()
		}
	}
}

func (d *Discovery) refreshPublicAddress() {
	mapped, err := d.holePuncher.DiscoverPublicAddr()
	if err != nil {
		return
	}

	// Update local peer's endpoints (with nil check for safety - bug fix: nil_pointer.2)
	localPeer := d.peerManager.LocalPeer()
	if localPeer != nil {
		localPeer.mu.Lock()
		localPeer.Endpoints = d.holePuncher.GetEndpoints()
		localPeer.mu.Unlock()
	}

	d.mu.RLock()
	callback := d.onDiscovered
	d.mu.RUnlock()

	if callback != nil {
		callback(localPeer, mapped)
	}
}

func (d *Discovery) maintenanceLoop() {
	defer d.wg.Done()

	// FIX: bug.multinode.12 - Stagger intervals to avoid synchronized load
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	retryTicker := time.NewTicker(15 * time.Second) // Changed from 10s to 15s
	defer retryTicker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.maintainConnections()
		case <-retryTicker.C:
			d.retryDirectConnections()
		}
	}
}

// FIX: bug.multinode.1 - Use bounded concurrency instead of spawning unlimited goroutines
func (d *Discovery) maintainConnections() {
	peers := d.peerManager.GetAllPeers()

	// Collect peers that need connection
	var peersToConnect []*Peer
	for _, peer := range peers {
		peer.mu.RLock()
		state := peer.State
		endpoints := peer.Endpoints
		peer.mu.RUnlock()

		if state == PeerStateDisconnected && len(endpoints) > 0 {
			peersToConnect = append(peersToConnect, peer)
		}
	}

	if len(peersToConnect) == 0 {
		return
	}

	// FIX: Limit concurrent connection attempts to prevent thundering herd
	maxConcurrent := 3
	if len(peersToConnect) < maxConcurrent {
		maxConcurrent = len(peersToConnect)
	}

	// Use semaphore pattern for bounded concurrency
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for i, peer := range peersToConnect {
		// FIX: Add jitter between connection attempts
		if i > 0 {
			jitter := time.Duration(100+rand.Intn(200)) * time.Millisecond
			time.Sleep(jitter)
		}

		wg.Add(1)
		go func(p *Peer) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release
			d.attemptConnection(p)
		}(peer)
	}

	// FIX: bug.production.10 - Use context-aware timeout instead of separate timer
	// This ensures the wait is interruptible by context cancellation
	waitCtx, waitCancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer waitCancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-waitCtx.Done():
		if d.ctx.Err() != nil {
			// Parent context cancelled, exit gracefully
			return
		}
		log.Printf("[Discovery] maintainConnections timeout, some peers may not be processed")
	}
}

// retryDirectConnections attempts to re-establish direct connections for connected peers
// This helps recover from NAT rebinding or when relay is being used unnecessarily
func (d *Discovery) retryDirectConnections() {
	peers := d.peerManager.GetAllPeers()

	for _, peer := range peers {
		peer.mu.RLock()
		state := peer.State
		endpoints := peer.Endpoints
		lastSeen := peer.LastSeen
		peer.mu.RUnlock()

		// Only retry for peers that have endpoints
		if len(endpoints) == 0 {
			continue
		}

		// IMPORTANT: Don't disturb working connections!
		// Only retry if:
		// 1. Peer is disconnected
		// 2. Peer is stuck in connecting for too long (>30s)
		// 3. Peer is connected but hasn't been seen in >30s (stale connection)
		shouldRetry := false
		reason := ""

		switch state {
		case PeerStateDisconnected:
			shouldRetry = true
			reason = "disconnected"
		case PeerStateConnecting:
			// Only retry if stuck for more than 30 seconds
			if time.Since(lastSeen) > 30*time.Second {
				shouldRetry = true
				reason = fmt.Sprintf("stuck connecting for %v", time.Since(lastSeen).Round(time.Second))
			}
		case PeerStateConnected:
			// Only retry if truly stale (>30s without activity)
			// 30s is long enough to avoid disrupting working connections
			// but short enough to recover from failed connections
			if time.Since(lastSeen) > 30*time.Second {
				shouldRetry = true
				reason = fmt.Sprintf("stale connection (last seen %v ago)", time.Since(lastSeen).Round(time.Second))
			}
			// If recently seen, DO NOT retry - connection is working!
		}

		if shouldRetry {
			log.Printf("[Discovery] Retrying connection to %s: %s", peer.Name, reason)
			peer.mu.Lock()
			peer.State = PeerStateDisconnected
			peer.mu.Unlock()
			go d.attemptConnection(peer)
		}
	}
}

func (d *Discovery) attemptConnection(peer *Peer) {
	peer.mu.Lock()
	if peer.State == PeerStateConnected {
		peer.mu.Unlock()
		return
	}
	if peer.State == PeerStateConnecting {
		// Already attempting, skip
		peer.mu.Unlock()
		return
	}
	endpoints := peer.Endpoints
	publicKey := peer.PublicKey
	peerName := peer.Name
	peer.mu.Unlock()

	if len(endpoints) == 0 {
		log.Printf("[Discovery] No endpoints for peer %s, skipping", peerName)
		return
	}

	// FIX: bug.multinode.2 - Reduced cooldown from 30s to 10s for multi-node
	// Check cooldown - don't punch same peer more than once per 10 seconds
	d.mu.Lock()
	lastPunch, exists := d.punchCooldown[publicKey]
	if exists && time.Since(lastPunch) < 10*time.Second {
		d.mu.Unlock()
		return
	}
	d.punchCooldown[publicKey] = time.Now()
	d.mu.Unlock()

	peer.mu.Lock()
	peer.State = PeerStateConnecting
	peer.mu.Unlock()

	// Get our endpoints to share with peer
	myEndpoints := d.holePuncher.GetEndpoints()

	// Send coordinated punch request via relay if available
	d.mu.RLock()
	relayClient := d.relayClient
	d.mu.RUnlock()

	if relayClient != nil && relayClient.IsConnected() {
		if err := relayClient.RequestPunch(publicKey, myEndpoints); err != nil {
			log.Printf("[Discovery] Could not send punch request via relay: %v", err)
		} else {
			log.Printf("[Discovery] Sent punch request to %s", peerName)
			time.Sleep(50 * time.Millisecond) // Short wait for relay to forward
		}
	}

	// Filter endpoints
	publicEndpoints, privateEndpoints := filterEndpoints(endpoints)
	allEndpoints := append(publicEndpoints, privateEndpoints...)

	log.Printf("[Discovery] Punching to %s (%d public, %d private endpoints)", peerName, len(publicEndpoints), len(privateEndpoints))

	// Send punch packets for 5 seconds (increased from 2s for multi-node congestion)
	// FIX: bug.multinode.9 - Adaptive timeout for multi-peer scenarios
	ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
	defer cancel() // Ensure context resources are cleaned up

	_, _ = d.holePuncher.SimultaneousPunch(ctx, allEndpoints, 5*time.Second)

	// Check if peer got connected via WireGuard callback
	peer.mu.Lock()
	if peer.State == PeerStateConnected {
		log.Printf("[Discovery] Peer %s connected successfully", peerName)
	} else {
		// Not connected yet, keep as connecting - will retry later
		peer.State = PeerStateDisconnected
		log.Printf("[Discovery] Peer %s punch sent, waiting for connection", peerName)
	}
	peer.mu.Unlock()
}

// filterEndpoints separates public and private IP endpoints
func filterEndpoints(endpoints []string) (public, private []string) {
	for _, ep := range endpoints {
		// Extract IP from endpoint (ip:port)
		host, _, err := net.SplitHostPort(ep)
		if err != nil {
			continue
		}

		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}

		if isPublicIP(ip) {
			public = append(public, ep)
		} else {
			private = append(private, ep)
		}
	}
	return
}

// isPublicIP checks if an IP is a public/routable IP
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return false // Skip IPv6 for now
	}

	// Check for private/special ranges
	// 10.0.0.0/8
	if ip4[0] == 10 {
		return false
	}
	// 172.16.0.0/12
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return false
	}
	// 192.168.0.0/16
	if ip4[0] == 192 && ip4[1] == 168 {
		return false
	}
	// 169.254.0.0/16 (link-local)
	if ip4[0] == 169 && ip4[1] == 254 {
		return false
	}
	// 127.0.0.0/8 (loopback)
	if ip4[0] == 127 {
		return false
	}
	// 100.64.0.0/10 (CGNAT) - but could be Tailscale/similar, allow it
	if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return true // Allow CGNAT as it might be a VPN provider's public IP
	}

	return true
}

// ConnectToPeer initiates a connection to a specific peer
func (d *Discovery) ConnectToPeer(publicKey string) error {
	peer := d.peerManager.GetPeer(publicKey)
	if peer == nil {
		// FIX: bug.production.5 - Return error when peer not found instead of silent nil
		return fmt.Errorf("peer not found: %s", publicKey)
	}

	go d.attemptConnection(peer)
	return nil
}

// Stop stops the discovery process
func (d *Discovery) Stop() {
	d.cancel()
	d.wg.Wait()
}
