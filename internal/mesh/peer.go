package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/selftunnel/selftunnel/internal/crypto"
)

type PeerState int

const (
	PeerStateDisconnected PeerState = iota
	PeerStateConnecting
	PeerStateConnected
)

type Peer struct {
	Name      string            `json:"name"`
	PublicKey string            `json:"public_key"`
	VirtualIP string            `json:"virtual_ip"`
	Endpoints []string          `json:"endpoints"`
	State     PeerState         `json:"state"`
	LastSeen  time.Time         `json:"last_seen"`
	TxBytes   uint64            `json:"tx_bytes"`
	RxBytes   uint64            `json:"rx_bytes"`
	Latency   time.Duration     `json:"latency"`
	Metadata  map[string]string `json:"metadata"`
	endpoint  *net.UDPAddr
	mu        sync.RWMutex
}

type PeerManager struct {
	localPeer    *Peer
	peers        map[string]*Peer
	peersByIP    map[string]*Peer
	mu           sync.RWMutex
	onPeerAdd    func(*Peer)
	onPeerRemove func(*Peer)
	onPeerUpdate func(*Peer)
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewPeerManager(localPeer *Peer) *PeerManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &PeerManager{
		localPeer: localPeer,
		peers:     make(map[string]*Peer),
		peersByIP: make(map[string]*Peer),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// SetCallbacks sets the event callbacks
func (pm *PeerManager) SetCallbacks(onAdd, onRemove, onUpdate func(*Peer)) {
	pm.onPeerAdd = onAdd
	pm.onPeerRemove = onRemove
	pm.onPeerUpdate = onUpdate
}

// AddPeer adds a new peer to the mesh
func (pm *PeerManager) AddPeer(peer *Peer) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.peers[peer.PublicKey]; exists {
		return fmt.Errorf("peer already exists: %s", peer.Name)
	}

	pm.peers[peer.PublicKey] = peer
	if peer.VirtualIP != "" {
		pm.peersByIP[peer.VirtualIP] = peer
	}

	if pm.onPeerAdd != nil {
		go pm.onPeerAdd(peer)
	}

	return nil
}

// RemovePeer removes a peer from the mesh
func (pm *PeerManager) RemovePeer(publicKey string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	peer, exists := pm.peers[publicKey]
	if !exists {
		return
	}

	delete(pm.peers, publicKey)
	if peer.VirtualIP != "" {
		delete(pm.peersByIP, peer.VirtualIP)
	}

	if pm.onPeerRemove != nil {
		go pm.onPeerRemove(peer)
	}
}

// UpdatePeer updates a peer's information
func (pm *PeerManager) UpdatePeer(publicKey string, update func(*Peer)) error {
	pm.mu.Lock()
	peer, exists := pm.peers[publicKey]
	pm.mu.Unlock()

	if !exists {
		return fmt.Errorf("peer not found: %s", publicKey)
	}

	peer.mu.Lock()
	update(peer)
	peer.mu.Unlock()

	if pm.onPeerUpdate != nil {
		go pm.onPeerUpdate(peer)
	}

	return nil
}

// GetPeer returns a peer by public key
func (pm *PeerManager) GetPeer(publicKey string) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.peers[publicKey]
}

// GetPeerByIP returns a peer by virtual IP
func (pm *PeerManager) GetPeerByIP(ip string) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.peersByIP[ip]
}

// GetPeerByName returns a peer by name (case-insensitive)
func (pm *PeerManager) GetPeerByName(name string) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	nameLower := strings.ToLower(name)
	for _, peer := range pm.peers {
		if strings.ToLower(peer.Name) == nameLower {
			return peer
		}
	}
	// Also check local peer
	if pm.localPeer != nil && strings.ToLower(pm.localPeer.Name) == nameLower {
		return pm.localPeer
	}
	return nil
}

// GetAllPeers returns all peers
func (pm *PeerManager) GetAllPeers() []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peers := make([]*Peer, 0, len(pm.peers))
	for _, p := range pm.peers {
		peers = append(peers, p)
	}
	return peers
}

// GetConnectedPeers returns only connected peers
func (pm *PeerManager) GetConnectedPeers() []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peers := make([]*Peer, 0)
	for _, p := range pm.peers {
		p.mu.RLock()
		state := p.State
		p.mu.RUnlock()
		if state == PeerStateConnected {
			peers = append(peers, p)
		}
	}
	return peers
}

// LocalPeer returns the local peer
func (pm *PeerManager) LocalPeer() *Peer {
	return pm.localPeer
}

// UpdateFromSignaling updates peers from signaling server data
func (pm *PeerManager) UpdateFromSignaling(peersData []byte) error {
	var remotePeers []*Peer
	if err := json.Unmarshal(peersData, &remotePeers); err != nil {
		return fmt.Errorf("failed to unmarshal peers: %w", err)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Track which peers we've seen
	seen := make(map[string]bool)

	for _, remotePeer := range remotePeers {
		// Skip self
		if remotePeer.PublicKey == pm.localPeer.PublicKey {
			continue
		}

		seen[remotePeer.PublicKey] = true

		if existing, exists := pm.peers[remotePeer.PublicKey]; exists {
			// Update existing peer
			existing.mu.Lock()
			existing.Endpoints = remotePeer.Endpoints
			existing.Metadata = remotePeer.Metadata
			existing.mu.Unlock()

			if pm.onPeerUpdate != nil {
				go pm.onPeerUpdate(existing)
			}
		} else {
			// Add new peer
			remotePeer.State = PeerStateDisconnected
			pm.peers[remotePeer.PublicKey] = remotePeer
			if remotePeer.VirtualIP != "" {
				pm.peersByIP[remotePeer.VirtualIP] = remotePeer
			}

			if pm.onPeerAdd != nil {
				go pm.onPeerAdd(remotePeer)
			}
		}
	}

	// Remove peers that are no longer in the network
	for pubKey, peer := range pm.peers {
		if !seen[pubKey] {
			delete(pm.peers, pubKey)
			if peer.VirtualIP != "" {
				delete(pm.peersByIP, peer.VirtualIP)
			}

			if pm.onPeerRemove != nil {
				go pm.onPeerRemove(peer)
			}
		}
	}

	return nil
}

// Close closes the peer manager
func (pm *PeerManager) Close() {
	pm.cancel()
}

// SetEndpoints safely updates a peer's endpoints
func (p *Peer) SetEndpoints(endpoints []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Endpoints = endpoints
}

// GetEndpoints safely gets a peer's endpoints
func (p *Peer) GetEndpoints() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Endpoints
}

// UpdateLastSeen updates the peer's last seen time and optionally sets state to connected
func (p *Peer) UpdateLastSeen(setConnected bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastSeen = time.Now()
	if setConnected && p.State != PeerStateConnected {
		p.State = PeerStateConnected
	}
}

// GetLastSeen safely gets the peer's last seen time
func (p *Peer) GetLastSeen() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.LastSeen
}

// GetState safely gets the peer's state
func (p *Peer) GetState() PeerState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.State
}

// SetState safely sets the peer's state
func (p *Peer) SetState(state PeerState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.State = state
}

// NewPeerFromKeys creates a new peer from key pair
func NewPeerFromKeys(name string, keyPair *crypto.KeyPair, virtualIP string) *Peer {
	return &Peer{
		Name:      name,
		PublicKey: crypto.ToBase64(keyPair.PublicKey),
		VirtualIP: virtualIP,
		Endpoints: []string{},
		State:     PeerStateDisconnected,
		Metadata:  make(map[string]string),
	}
}
