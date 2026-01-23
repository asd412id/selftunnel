package signaling

import (
	"testing"
	"time"

	"github.com/selftunnel/selftunnel/internal/mesh"
)

func TestNewClient(t *testing.T) {
	client := NewClient(
		"https://example.com",
		"network-id",
		"network-secret",
	)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}
}

func TestSetLocalPeer(t *testing.T) {
	client := NewClient("https://example.com", "net", "secret")

	peer := &mesh.Peer{
		Name:      "test-node",
		PublicKey: "test-key",
		VirtualIP: "10.99.0.1",
	}

	client.SetLocalPeer(peer)

	// Read back via internal access (normally would verify via Register)
	client.mu.RLock()
	localPeer := client.localPeer
	client.mu.RUnlock()

	if localPeer == nil {
		t.Error("localPeer should be set")
	}
	if localPeer.Name != "test-node" {
		t.Errorf("localPeer.Name: got %s, want test-node", localPeer.Name)
	}
}

func TestSetPeersUpdateCallback(t *testing.T) {
	client := NewClient("https://example.com", "net", "secret")

	client.SetPeersUpdateCallback(func(peers []*mesh.Peer) {
		// callback placeholder
	})

	client.mu.RLock()
	callback := client.onPeersUpdate
	client.mu.RUnlock()

	if callback == nil {
		t.Error("onPeersUpdate should be set")
	}
}

func TestSignalingPeerToMeshPeer(t *testing.T) {
	sp := &SignalingPeer{
		Name:      "test-node",
		PublicKey: "test-key",
		VirtualIP: "10.99.0.5",
		Endpoints: []string{"1.2.3.4:51820", "5.6.7.8:51820"},
		LastSeen:  time.Now().UnixMilli(),
	}

	mp := sp.ToMeshPeer()

	if mp.Name != sp.Name {
		t.Errorf("Name: got %s, want %s", mp.Name, sp.Name)
	}
	if mp.PublicKey != sp.PublicKey {
		t.Errorf("PublicKey: got %s, want %s", mp.PublicKey, sp.PublicKey)
	}
	if mp.VirtualIP != sp.VirtualIP {
		t.Errorf("VirtualIP: got %s, want %s", mp.VirtualIP, sp.VirtualIP)
	}
	if len(mp.Endpoints) != len(sp.Endpoints) {
		t.Errorf("Endpoints length: got %d, want %d", len(mp.Endpoints), len(sp.Endpoints))
	}
	if mp.LastSeen.IsZero() {
		t.Error("LastSeen should be set")
	}
}

func TestFilterChangedPeers(t *testing.T) {
	client := NewClient("https://example.com", "net", "secret")

	// First call - all peers are new
	peers1 := []*mesh.Peer{
		{Name: "peer1", PublicKey: "key1", Endpoints: []string{"1.1.1.1:51820"}},
		{Name: "peer2", PublicKey: "key2", Endpoints: []string{"2.2.2.2:51820"}},
	}

	changed1 := client.filterChangedPeers(peers1)
	if len(changed1) != 2 {
		t.Errorf("First call: expected 2 changed, got %d", len(changed1))
	}

	// Second call with same peers - no changes
	peers2 := []*mesh.Peer{
		{Name: "peer1", PublicKey: "key1", Endpoints: []string{"1.1.1.1:51820"}},
		{Name: "peer2", PublicKey: "key2", Endpoints: []string{"2.2.2.2:51820"}},
	}

	changed2 := client.filterChangedPeers(peers2)
	if len(changed2) != 0 {
		t.Errorf("Second call (no changes): expected 0 changed, got %d", len(changed2))
	}

	// Third call with endpoint change
	peers3 := []*mesh.Peer{
		{Name: "peer1", PublicKey: "key1", Endpoints: []string{"3.3.3.3:51820"}}, // Changed
		{Name: "peer2", PublicKey: "key2", Endpoints: []string{"2.2.2.2:51820"}}, // Same
	}

	changed3 := client.filterChangedPeers(peers3)
	if len(changed3) != 1 {
		t.Errorf("Third call (1 change): expected 1 changed, got %d", len(changed3))
	}
	if len(changed3) > 0 && changed3[0].PublicKey != "key1" {
		t.Error("Changed peer should be key1")
	}

	// Fourth call with new peer
	peers4 := []*mesh.Peer{
		{Name: "peer1", PublicKey: "key1", Endpoints: []string{"3.3.3.3:51820"}},
		{Name: "peer2", PublicKey: "key2", Endpoints: []string{"2.2.2.2:51820"}},
		{Name: "peer3", PublicKey: "key3", Endpoints: []string{"4.4.4.4:51820"}}, // New
	}

	changed4 := client.filterChangedPeers(peers4)
	if len(changed4) != 1 {
		t.Errorf("Fourth call (1 new): expected 1 changed, got %d", len(changed4))
	}
	if len(changed4) > 0 && changed4[0].PublicKey != "key3" {
		t.Error("Changed peer should be key3 (new)")
	}
}

func TestRegisterRequestStruct(t *testing.T) {
	peer := &mesh.Peer{
		Name:      "test",
		PublicKey: "key",
	}

	req := RegisterRequest{
		NetworkID:     "net-123",
		NetworkSecret: "secret",
		Peer:          peer,
	}

	if req.NetworkID != "net-123" {
		t.Errorf("NetworkID: got %s, want net-123", req.NetworkID)
	}
	if req.Peer.Name != "test" {
		t.Errorf("Peer.Name: got %s, want test", req.Peer.Name)
	}
}

func TestRegisterResponseStruct(t *testing.T) {
	resp := RegisterResponse{
		Success:   true,
		VirtualIP: "10.99.0.5",
		Message:   "Registered successfully",
	}

	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.VirtualIP != "10.99.0.5" {
		t.Errorf("VirtualIP: got %s, want 10.99.0.5", resp.VirtualIP)
	}
}

func TestExchangeRequestStruct(t *testing.T) {
	req := ExchangeRequest{
		NetworkID:     "net-123",
		NetworkSecret: "secret",
		FromPublicKey: "from-key",
		ToPublicKey:   "to-key",
		Endpoints:     []string{"1.2.3.4:51820"},
	}

	if req.FromPublicKey != "from-key" {
		t.Errorf("FromPublicKey: got %s, want from-key", req.FromPublicKey)
	}
	if req.ToPublicKey != "to-key" {
		t.Errorf("ToPublicKey: got %s, want to-key", req.ToPublicKey)
	}
}

func TestRegisterWithoutLocalPeer(t *testing.T) {
	client := NewClient("https://example.com", "net", "secret")

	// Should fail without local peer
	_, err := client.Register()
	if err == nil {
		t.Error("Register should fail without local peer")
	}
}

func TestHeartbeatWithoutLocalPeer(t *testing.T) {
	client := NewClient("https://example.com", "net", "secret")

	err := client.Heartbeat()
	if err == nil {
		t.Error("Heartbeat should fail without local peer")
	}
}

func TestExchangeEndpointsWithoutLocalPeer(t *testing.T) {
	client := NewClient("https://example.com", "net", "secret")

	err := client.ExchangeEndpoints("target-key", []string{"1.2.3.4:51820"})
	if err == nil {
		t.Error("ExchangeEndpoints should fail without local peer")
	}
}
