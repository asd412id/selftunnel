package mesh

import (
	"context"
	"sync"
	"time"

	"github.com/selftunnel/selftunnel/internal/nat"
)

type Discovery struct {
	peerManager  *PeerManager
	holePuncher  *nat.HolePuncher
	onDiscovered func(*Peer, *nat.MappedAddress)
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

func NewDiscovery(pm *PeerManager, hp *nat.HolePuncher) *Discovery {
	ctx, cancel := context.WithCancel(context.Background())

	return &Discovery{
		peerManager: pm,
		holePuncher: hp,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// SetDiscoveryCallback sets the callback for when a peer is discovered
func (d *Discovery) SetDiscoveryCallback(callback func(*Peer, *nat.MappedAddress)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onDiscovered = callback
}

// Start starts the discovery process
func (d *Discovery) Start() error {
	// Discover our public address first
	mapped, err := d.holePuncher.DiscoverPublicAddr()
	if err != nil {
		// Not fatal - we might be on a local network
		mapped = nil
	}

	// Update local peer's endpoints
	localPeer := d.peerManager.LocalPeer()
	localPeer.mu.Lock()
	localPeer.Endpoints = d.holePuncher.GetEndpoints()
	localPeer.mu.Unlock()

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

	// Update local peer's endpoints
	localPeer := d.peerManager.LocalPeer()
	localPeer.mu.Lock()
	localPeer.Endpoints = d.holePuncher.GetEndpoints()
	localPeer.mu.Unlock()

	d.mu.RLock()
	callback := d.onDiscovered
	d.mu.RUnlock()

	if callback != nil {
		callback(localPeer, mapped)
	}
}

func (d *Discovery) maintenanceLoop() {
	defer d.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.maintainConnections()
		}
	}
}

func (d *Discovery) maintainConnections() {
	peers := d.peerManager.GetAllPeers()

	for _, peer := range peers {
		peer.mu.RLock()
		state := peer.State
		endpoints := peer.Endpoints
		peer.mu.RUnlock()

		if state == PeerStateDisconnected && len(endpoints) > 0 {
			// Try to establish connection
			go d.attemptConnection(peer)
		}
	}
}

func (d *Discovery) attemptConnection(peer *Peer) {
	peer.mu.Lock()
	if peer.State != PeerStateDisconnected {
		peer.mu.Unlock()
		return
	}
	peer.State = PeerStateConnecting
	endpoints := peer.Endpoints
	peer.mu.Unlock()

	// Try hole punching
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()

	addr, err := d.holePuncher.SimultaneousPunch(ctx, endpoints, 10*time.Second)

	peer.mu.Lock()
	if err != nil {
		peer.State = PeerStateDisconnected
	} else {
		peer.State = PeerStateConnected
		peer.endpoint = addr
		peer.LastSeen = time.Now()
	}
	peer.mu.Unlock()
}

// ConnectToPeer initiates a connection to a specific peer
func (d *Discovery) ConnectToPeer(publicKey string) error {
	peer := d.peerManager.GetPeer(publicKey)
	if peer == nil {
		return nil
	}

	go d.attemptConnection(peer)
	return nil
}

// Stop stops the discovery process
func (d *Discovery) Stop() {
	d.cancel()
	d.wg.Wait()
}
