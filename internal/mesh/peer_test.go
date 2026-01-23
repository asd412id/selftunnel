package mesh

import (
	"testing"
	"time"
)

func TestNewPeerManager(t *testing.T) {
	localPeer := &Peer{
		Name:      "local",
		PublicKey: "local-key",
		VirtualIP: "10.99.0.1",
	}

	pm := NewPeerManager(localPeer)
	if pm == nil {
		t.Fatal("NewPeerManager returned nil")
	}

	// Check local peer
	if pm.LocalPeer() == nil {
		t.Error("LocalPeer should not be nil")
	}
	if pm.LocalPeer().Name != "local" {
		t.Errorf("LocalPeer name: got %s, want local", pm.LocalPeer().Name)
	}
}

func TestAddAndGetPeer(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})

	peer := &Peer{
		Name:      "remote",
		PublicKey: "remote-key",
		VirtualIP: "10.99.0.2",
		Endpoints: []string{"1.2.3.4:51820"},
	}

	// Add peer
	err := pm.AddPeer(peer)
	if err != nil {
		t.Fatalf("Failed to add peer: %v", err)
	}

	// Get by public key
	got := pm.GetPeer("remote-key")
	if got == nil {
		t.Fatal("GetPeer returned nil")
	}
	if got.Name != "remote" {
		t.Errorf("Peer name: got %s, want remote", got.Name)
	}

	// Get by IP
	gotByIP := pm.GetPeerByIP("10.99.0.2")
	if gotByIP == nil {
		t.Fatal("GetPeerByIP returned nil")
	}
	if gotByIP.PublicKey != "remote-key" {
		t.Error("GetPeerByIP returned wrong peer")
	}

	// Get by name
	gotByName := pm.GetPeerByName("remote")
	if gotByName == nil {
		t.Fatal("GetPeerByName returned nil")
	}

	// Case insensitive
	gotByName2 := pm.GetPeerByName("REMOTE")
	if gotByName2 == nil {
		t.Fatal("GetPeerByName should be case insensitive")
	}
}

func TestAddDuplicatePeer(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})

	peer := &Peer{
		Name:      "remote",
		PublicKey: "remote-key",
	}

	pm.AddPeer(peer)

	// Add duplicate
	err := pm.AddPeer(&Peer{Name: "remote2", PublicKey: "remote-key"})
	if err == nil {
		t.Error("Adding duplicate peer should fail")
	}
}

func TestRemovePeer(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})

	peer := &Peer{
		Name:      "remote",
		PublicKey: "remote-key",
		VirtualIP: "10.99.0.2",
	}
	pm.AddPeer(peer)

	// Remove
	pm.RemovePeer("remote-key")

	// Should be gone
	if pm.GetPeer("remote-key") != nil {
		t.Error("Peer should be removed")
	}
	if pm.GetPeerByIP("10.99.0.2") != nil {
		t.Error("Peer should be removed from IP index")
	}
}

func TestGetAllPeers(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})

	// Add multiple peers
	pm.AddPeer(&Peer{Name: "peer1", PublicKey: "key1"})
	pm.AddPeer(&Peer{Name: "peer2", PublicKey: "key2"})
	pm.AddPeer(&Peer{Name: "peer3", PublicKey: "key3"})

	peers := pm.GetAllPeers()
	if len(peers) != 3 {
		t.Errorf("Expected 3 peers, got %d", len(peers))
	}
}

func TestGetConnectedPeers(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})

	pm.AddPeer(&Peer{Name: "peer1", PublicKey: "key1", State: PeerStateConnected})
	pm.AddPeer(&Peer{Name: "peer2", PublicKey: "key2", State: PeerStateDisconnected})
	pm.AddPeer(&Peer{Name: "peer3", PublicKey: "key3", State: PeerStateConnected})

	connected := pm.GetConnectedPeers()
	if len(connected) != 2 {
		t.Errorf("Expected 2 connected peers, got %d", len(connected))
	}
}

func TestPeerState(t *testing.T) {
	peer := &Peer{
		Name:      "test",
		PublicKey: "test-key",
		State:     PeerStateDisconnected,
	}

	if peer.GetState() != PeerStateDisconnected {
		t.Error("Initial state should be disconnected")
	}

	peer.SetState(PeerStateConnecting)
	if peer.GetState() != PeerStateConnecting {
		t.Error("State should be connecting")
	}

	peer.SetState(PeerStateConnected)
	if peer.GetState() != PeerStateConnected {
		t.Error("State should be connected")
	}
}

func TestPeerEndpoints(t *testing.T) {
	peer := &Peer{
		Name:      "test",
		PublicKey: "test-key",
		Endpoints: []string{"1.2.3.4:51820"},
	}

	// Get endpoints
	eps := peer.GetEndpoints()
	if len(eps) != 1 {
		t.Errorf("Expected 1 endpoint, got %d", len(eps))
	}

	// Set new endpoints (primary changed)
	changed := peer.SetEndpoints([]string{"5.6.7.8:51820", "1.2.3.4:51820"})
	if !changed {
		t.Error("SetEndpoints should return true when primary endpoint changes")
	}

	// Set same endpoints (primary not changed)
	changed = peer.SetEndpoints([]string{"5.6.7.8:51820", "9.9.9.9:51820"})
	if changed {
		t.Error("SetEndpoints should return false when primary endpoint is same")
	}
}

func TestPeerLastSeen(t *testing.T) {
	peer := &Peer{
		Name:      "test",
		PublicKey: "test-key",
		State:     PeerStateDisconnected,
	}

	// Initial LastSeen is zero
	if !peer.GetLastSeen().IsZero() {
		t.Error("Initial LastSeen should be zero")
	}

	// Update last seen
	peer.UpdateLastSeen(false)
	if peer.GetLastSeen().IsZero() {
		t.Error("LastSeen should be updated")
	}
	if peer.GetState() != PeerStateDisconnected {
		t.Error("State should not change when setConnected is false")
	}

	// Update last seen with setConnected
	peer.UpdateLastSeen(true)
	if peer.GetState() != PeerStateConnected {
		t.Error("State should be connected when setConnected is true")
	}
}

func TestUpdatePeer(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})

	peer := &Peer{
		Name:      "remote",
		PublicKey: "remote-key",
		VirtualIP: "10.99.0.2",
	}
	pm.AddPeer(peer)

	// Update peer
	err := pm.UpdatePeer("remote-key", func(p *Peer) {
		p.State = PeerStateConnected
		p.LastSeen = time.Now()
	})
	if err != nil {
		t.Fatalf("Failed to update peer: %v", err)
	}

	// Verify update
	updated := pm.GetPeer("remote-key")
	if updated.GetState() != PeerStateConnected {
		t.Error("Peer state should be connected after update")
	}
}

func TestUpdatePeerNotFound(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})

	err := pm.UpdatePeer("nonexistent", func(p *Peer) {
		p.State = PeerStateConnected
	})
	if err == nil {
		t.Error("Updating nonexistent peer should fail")
	}
}
