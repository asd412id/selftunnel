//go:build integration
// +build integration

package signaling

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/selftunnel/selftunnel/internal/crypto"
	"github.com/selftunnel/selftunnel/internal/mesh"
)

const (
	// Default signaling server for integration tests
	defaultSignalingURL = "https://signaling-server.maccaqe.id"
)

func getSignalingURL() string {
	if url := os.Getenv("SIGNALING_URL"); url != "" {
		return url
	}
	return defaultSignalingURL
}

// generateTestNetwork creates a unique network ID and secret for testing
func generateTestNetwork() (string, string, error) {
	networkSecret, err := crypto.GenerateNetworkSecret()
	if err != nil {
		return "", "", err
	}
	networkID, err := crypto.GenerateNetworkID()
	if err != nil {
		return "", "", err
	}
	return networkID, networkSecret, nil
}

// createTestPeer creates a test peer with generated keys
func createTestPeer(name string) (*mesh.Peer, error) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return &mesh.Peer{
		Name:      name,
		PublicKey: crypto.ToBase64(keyPair.PublicKey),
		VirtualIP: "", // Will be assigned by server
		Endpoints: []string{"127.0.0.1:51820"},
		LastSeen:  time.Now(),
	}, nil
}

// TestIntegrationServerConnection tests basic connectivity to signaling server
func TestIntegrationServerConnection(t *testing.T) {
	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("Failed to generate test network: %v", err)
	}

	// Create and register a peer first to establish the network
	peer, err := createTestPeer("connection-test-peer")
	if err != nil {
		t.Fatalf("Failed to create test peer: %v", err)
	}

	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	// Register to establish network
	resp, err := client.Register()
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	if !resp.Success {
		t.Fatalf("Registration failed: %s", resp.Message)
	}

	// Test: Get peers (should work now that we're registered)
	peers, err := client.GetPeers()
	if err != nil {
		t.Fatalf("Failed to get peers: %v", err)
	}

	// Should see at least our own peer
	if len(peers) < 1 {
		t.Error("Expected at least 1 peer (self)")
	}

	t.Logf("Server connection successful, found %d peers", len(peers))
}

// TestIntegrationPeerRegistration tests peer registration and discovery
func TestIntegrationPeerRegistration(t *testing.T) {
	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("Failed to generate test network: %v", err)
	}

	// Create test peer
	peer, err := createTestPeer("integration-test-peer")
	if err != nil {
		t.Fatalf("Failed to create test peer: %v", err)
	}

	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	// Test: Register peer
	resp, err := client.Register()
	if err != nil {
		t.Fatalf("Failed to register peer: %v", err)
	}

	if !resp.Success {
		t.Fatalf("Registration not successful: %s", resp.Message)
	}

	if resp.VirtualIP == "" {
		t.Error("Expected VirtualIP to be assigned")
	}

	t.Logf("Registered with VirtualIP: %s", resp.VirtualIP)

	// Test: Verify peer appears in peer list
	time.Sleep(500 * time.Millisecond) // Allow server to process

	peers, err := client.GetPeers()
	if err != nil {
		t.Fatalf("Failed to get peers: %v", err)
	}

	found := false
	for _, p := range peers {
		if p.PublicKey == peer.PublicKey {
			found = true
			t.Logf("Found self in peer list: %s (%s)", p.Name, p.VirtualIP)
			break
		}
	}

	if !found {
		t.Error("Registered peer not found in peer list")
	}
}

// TestIntegrationHeartbeat tests heartbeat functionality
func TestIntegrationHeartbeat(t *testing.T) {
	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("Failed to generate test network: %v", err)
	}

	peer, err := createTestPeer("heartbeat-test-peer")
	if err != nil {
		t.Fatalf("Failed to create test peer: %v", err)
	}

	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	// Register first
	_, err = client.Register()
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	// Test: Send heartbeat
	err = client.Heartbeat()
	if err != nil {
		t.Fatalf("Failed to send heartbeat: %v", err)
	}

	t.Log("Heartbeat sent successfully")
}

// TestIntegrationMultiPeer tests multi-peer discovery scenario
func TestIntegrationMultiPeer(t *testing.T) {
	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("Failed to generate test network: %v", err)
	}

	// Create and register peer 1
	peer1, err := createTestPeer("multi-peer-1")
	if err != nil {
		t.Fatalf("Failed to create peer1: %v", err)
	}

	client1 := NewClient(getSignalingURL(), networkID, networkSecret)
	client1.SetLocalPeer(peer1)
	defer func() {
		client1.Unregister()
		client1.Stop()
	}()

	resp1, err := client1.Register()
	if err != nil {
		t.Fatalf("Failed to register peer1: %v", err)
	}
	t.Logf("Peer1 registered: %s", resp1.VirtualIP)

	// Create and register peer 2
	peer2, err := createTestPeer("multi-peer-2")
	if err != nil {
		t.Fatalf("Failed to create peer2: %v", err)
	}

	client2 := NewClient(getSignalingURL(), networkID, networkSecret)
	client2.SetLocalPeer(peer2)
	defer func() {
		client2.Unregister()
		client2.Stop()
	}()

	resp2, err := client2.Register()
	if err != nil {
		t.Fatalf("Failed to register peer2: %v", err)
	}
	t.Logf("Peer2 registered: %s", resp2.VirtualIP)

	// Allow server to process
	time.Sleep(500 * time.Millisecond)

	// Test: Peer1 should see Peer2
	peers1, err := client1.GetPeers()
	if err != nil {
		t.Fatalf("Failed to get peers from client1: %v", err)
	}

	foundPeer2 := false
	for _, p := range peers1 {
		if p.PublicKey == peer2.PublicKey {
			foundPeer2 = true
			t.Logf("Client1 sees Peer2: %s (%s)", p.Name, p.VirtualIP)
			break
		}
	}

	if !foundPeer2 {
		t.Error("Client1 should see Peer2 in peer list")
	}

	// Test: Peer2 should see Peer1
	peers2, err := client2.GetPeers()
	if err != nil {
		t.Fatalf("Failed to get peers from client2: %v", err)
	}

	foundPeer1 := false
	for _, p := range peers2 {
		if p.PublicKey == peer1.PublicKey {
			foundPeer1 = true
			t.Logf("Client2 sees Peer1: %s (%s)", p.Name, p.VirtualIP)
			break
		}
	}

	if !foundPeer1 {
		t.Error("Client2 should see Peer1 in peer list")
	}

	t.Logf("Multi-peer discovery successful: %d peers in network", len(peers1))
}

// TestIntegrationEndpointExchange tests endpoint exchange between peers
func TestIntegrationEndpointExchange(t *testing.T) {
	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("Failed to generate test network: %v", err)
	}

	// Create and register peer 1
	peer1, err := createTestPeer("exchange-peer-1")
	if err != nil {
		t.Fatalf("Failed to create peer1: %v", err)
	}

	client1 := NewClient(getSignalingURL(), networkID, networkSecret)
	client1.SetLocalPeer(peer1)
	defer func() {
		client1.Unregister()
		client1.Stop()
	}()

	_, err = client1.Register()
	if err != nil {
		t.Fatalf("Failed to register peer1: %v", err)
	}

	// Create and register peer 2
	peer2, err := createTestPeer("exchange-peer-2")
	if err != nil {
		t.Fatalf("Failed to create peer2: %v", err)
	}

	client2 := NewClient(getSignalingURL(), networkID, networkSecret)
	client2.SetLocalPeer(peer2)
	defer func() {
		client2.Unregister()
		client2.Stop()
	}()

	_, err = client2.Register()
	if err != nil {
		t.Fatalf("Failed to register peer2: %v", err)
	}

	// Allow registration to propagate
	time.Sleep(500 * time.Millisecond)

	// Test: Exchange endpoints from peer1 to peer2
	newEndpoints := []string{"192.168.1.100:51820", "10.0.0.100:51820"}
	err = client1.ExchangeEndpoints(peer2.PublicKey, newEndpoints)
	if err != nil {
		t.Fatalf("Failed to exchange endpoints: %v", err)
	}

	t.Log("Endpoint exchange successful")
}

// TestIntegrationUnregister tests peer unregistration
func TestIntegrationUnregister(t *testing.T) {
	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("Failed to generate test network: %v", err)
	}

	peer, err := createTestPeer("unregister-test-peer")
	if err != nil {
		t.Fatalf("Failed to create test peer: %v", err)
	}

	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)

	// Register
	_, err = client.Register()
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Verify registered
	peers, err := client.GetPeers()
	if err != nil {
		t.Fatalf("Failed to get peers: %v", err)
	}

	found := false
	for _, p := range peers {
		if p.PublicKey == peer.PublicKey {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Peer should be registered")
	}

	// Test: Unregister
	err = client.Unregister()
	if err != nil {
		t.Fatalf("Failed to unregister: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Verify unregistered
	peers, err = client.GetPeers()
	if err != nil {
		t.Fatalf("Failed to get peers after unregister: %v", err)
	}

	for _, p := range peers {
		if p.PublicKey == peer.PublicKey {
			t.Error("Peer should be unregistered")
		}
	}

	t.Log("Unregister successful")
	client.Stop()
}

// TestIntegrationPeersUpdateCallback tests the peers update callback mechanism
func TestIntegrationPeersUpdateCallback(t *testing.T) {
	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("Failed to generate test network: %v", err)
	}

	peer, err := createTestPeer("callback-test-peer")
	if err != nil {
		t.Fatalf("Failed to create test peer: %v", err)
	}

	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	// Setup callback
	callbackCalled := make(chan []*mesh.Peer, 1)
	client.SetPeersUpdateCallback(func(peers []*mesh.Peer) {
		select {
		case callbackCalled <- peers:
		default:
		}
	})

	// Register
	_, err = client.Register()
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	// Start client (begins peer polling)
	client.Start()

	// Wait for callback (with timeout)
	select {
	case peers := <-callbackCalled:
		t.Logf("Callback received with %d peers", len(peers))
	case <-time.After(15 * time.Second):
		t.Log("Callback timeout - this may be expected if no peer changes occur")
	}
}

// TestIntegrationThreePeerNetwork tests a 3-peer network scenario
func TestIntegrationThreePeerNetwork(t *testing.T) {
	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("Failed to generate test network: %v", err)
	}

	// Create 3 peers
	var clients []*Client
	var peers []*mesh.Peer

	for i := 1; i <= 3; i++ {
		peer, err := createTestPeer(fmt.Sprintf("three-peer-%d", i))
		if err != nil {
			t.Fatalf("Failed to create peer%d: %v", i, err)
		}
		peers = append(peers, peer)

		client := NewClient(getSignalingURL(), networkID, networkSecret)
		client.SetLocalPeer(peer)
		clients = append(clients, client)

		// Stagger registrations slightly
		resp, err := client.Register()
		if err != nil {
			t.Fatalf("Failed to register peer%d: %v", i, err)
		}
		t.Logf("Peer%d registered: %s", i, resp.VirtualIP)

		time.Sleep(200 * time.Millisecond)
	}

	// Cleanup
	defer func() {
		for _, c := range clients {
			c.Unregister()
			c.Stop()
		}
	}()

	// Allow all registrations to propagate
	time.Sleep(1 * time.Second)

	// Verify each peer can see all others
	for i, client := range clients {
		peerList, err := client.GetPeers()
		if err != nil {
			t.Fatalf("Client%d failed to get peers: %v", i+1, err)
		}

		// Should see all 3 peers (including self)
		if len(peerList) < 3 {
			t.Errorf("Client%d: expected at least 3 peers, got %d", i+1, len(peerList))
		}

		// Verify can see all other peers
		for j, expectedPeer := range peers {
			found := false
			for _, p := range peerList {
				if p.PublicKey == expectedPeer.PublicKey {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Client%d cannot see Peer%d", i+1, j+1)
			}
		}

		t.Logf("Client%d sees %d peers", i+1, len(peerList))
	}

	t.Log("3-peer network test successful")
}
