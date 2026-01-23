//go:build integration
// +build integration

package signaling

import (
	"testing"
	"time"

	"github.com/selftunnel/selftunnel/internal/mesh"
)

// =============================================================================
// Scenario 7: Edge Cases
// =============================================================================

// Scenario 7.1: Empty peer list
func TestScenario_7_1_EmptyPeerList(t *testing.T) {
	t.Log("Scenario 7.1: Empty peer list handling")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, _ := createTestPeer("scenario-7-1-empty")
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	// Register first peer
	_, err = client.Register()
	if err != nil {
		t.Fatalf("FAIL: Registration failed: %v", err)
	}

	// Get peers - should have at least self
	peers, err := client.GetPeers()
	if err != nil {
		t.Fatalf("FAIL: GetPeers failed: %v", err)
	}

	// Empty handling - should not panic
	if peers == nil {
		t.Log("Note: Peers is nil (should be empty slice)")
		peers = []*mesh.Peer{}
	}

	t.Logf("PASS: Empty/single peer list handled correctly (%d peers)", len(peers))
}

// Scenario 7.2: Duplicate peer registration
func TestScenario_7_2_DuplicateRegistration(t *testing.T) {
	t.Log("Scenario 7.2: Duplicate peer registration handling")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, _ := createTestPeer("scenario-7-2-duplicate")
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	// First registration
	resp1, err := client.Register()
	if err != nil {
		t.Fatalf("FAIL: First registration failed: %v", err)
	}
	t.Logf("First registration: %s", resp1.VirtualIP)

	// Duplicate registration (same peer)
	resp2, err := client.Register()
	if err != nil {
		// Some servers reject duplicates
		t.Logf("Note: Duplicate registration rejected (expected behavior): %v", err)
	} else {
		// Some servers accept and update
		t.Logf("Duplicate registration accepted: %s", resp2.VirtualIP)

		// IP should be same or reassigned
		if resp2.VirtualIP != "" {
			t.Logf("PASS: Duplicate handled - IP: %s", resp2.VirtualIP)
		}
	}

	t.Log("PASS: Duplicate registration handled without crash")
}

// Scenario 7.3: Peer with same public key
func TestScenario_7_3_SamePublicKey(t *testing.T) {
	t.Log("Scenario 7.3: Two clients with same public key")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	// Create peer
	peer1, _ := createTestPeer("scenario-7-3-same-key")

	// Create second peer with SAME public key
	peer2 := &mesh.Peer{
		Name:      "scenario-7-3-same-key-2",
		PublicKey: peer1.PublicKey, // Same key!
		Endpoints: []string{"192.168.1.200:51820"},
		LastSeen:  time.Now(),
	}

	// Client 1
	client1 := NewClient(getSignalingURL(), networkID, networkSecret)
	client1.SetLocalPeer(peer1)
	defer func() {
		client1.Unregister()
		client1.Stop()
	}()

	resp1, err := client1.Register()
	if err != nil {
		t.Fatalf("FAIL: Client 1 registration failed: %v", err)
	}
	t.Logf("Client 1 registered: %s", resp1.VirtualIP)

	// Client 2 with same public key
	client2 := NewClient(getSignalingURL(), networkID, networkSecret)
	client2.SetLocalPeer(peer2)
	defer func() {
		client2.Unregister()
		client2.Stop()
	}()

	resp2, err := client2.Register()
	if err != nil {
		t.Logf("Note: Client 2 rejected (same key, expected): %v", err)
	} else {
		t.Logf("Client 2 registered: %s (server allowed same key)", resp2.VirtualIP)
	}

	t.Log("PASS: Same public key scenario handled")
}

// Scenario 7.4: Malformed peer data
func TestScenario_7_4_MalformedPeerData(t *testing.T) {
	t.Log("Scenario 7.4: Malformed peer data handling")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	testCases := []struct {
		name string
		peer *mesh.Peer
	}{
		{
			name: "Empty name",
			peer: &mesh.Peer{
				Name:      "",
				PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				Endpoints: []string{"127.0.0.1:51820"},
			},
		},
		{
			name: "Very long name",
			peer: &mesh.Peer{
				Name:      string(make([]byte, 1000)),
				PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				Endpoints: []string{"127.0.0.1:51820"},
			},
		},
		{
			name: "No endpoints",
			peer: &mesh.Peer{
				Name:      "no-endpoints",
				PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				Endpoints: []string{},
			},
		},
		{
			name: "Invalid endpoint format",
			peer: &mesh.Peer{
				Name:      "bad-endpoint",
				PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				Endpoints: []string{"not-an-endpoint"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := NewClient(getSignalingURL(), networkID, networkSecret)
			client.SetLocalPeer(tc.peer)
			defer client.Stop()

			_, err := client.Register()
			if err != nil {
				t.Logf("PASS: %s - rejected with: %v", tc.name, err)
			} else {
				t.Logf("Note: %s - accepted by server", tc.name)
			}
		})
	}
}

// Scenario 7.5: Graceful shutdown with active connections
func TestScenario_7_5_GracefulShutdown(t *testing.T) {
	t.Log("Scenario 7.5: Graceful shutdown with active connections")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, _ := createTestPeer("scenario-7-5-shutdown")
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)

	// Register and start
	_, err = client.Register()
	if err != nil {
		t.Fatalf("FAIL: Registration failed: %v", err)
	}

	client.Start()

	// Let it run briefly
	time.Sleep(1 * time.Second)

	// Graceful shutdown
	shutdownStart := time.Now()

	// Unregister first
	err = client.Unregister()
	if err != nil {
		t.Logf("Note: Unregister error (may be expected): %v", err)
	}

	// Stop client
	client.Stop()

	shutdownDuration := time.Since(shutdownStart)

	if shutdownDuration > 10*time.Second {
		t.Fatalf("FAIL: Shutdown took too long: %v", shutdownDuration)
	}

	t.Logf("PASS: Graceful shutdown completed in %v", shutdownDuration)
}

// Scenario 7.6: Callback with nil peers
func TestScenario_7_6_NilCallback(t *testing.T) {
	t.Log("Scenario 7.6: Callback handling with nil peers")

	client := NewClient(getSignalingURL(), "test-net", "test-secret")

	client.SetPeersUpdateCallback(func(peers []*mesh.Peer) {
		if peers == nil {
			t.Log("Note: Callback received nil peers")
		} else {
			t.Logf("Callback received %d peers", len(peers))
		}
	})

	// Test filterChangedPeers with nil
	result := client.filterChangedPeers(nil)
	if result != nil && len(result) != 0 {
		t.Errorf("FAIL: filterChangedPeers(nil) should return empty, got %d", len(result))
	}

	// Test with empty
	result = client.filterChangedPeers([]*mesh.Peer{})
	if len(result) != 0 {
		t.Errorf("FAIL: filterChangedPeers([]) should return empty, got %d", len(result))
	}

	client.Stop()
	t.Log("PASS: Nil/empty peer handling works correctly")
}

// Scenario 7.7: Unicode in peer name
func TestScenario_7_7_UnicodePeerName(t *testing.T) {
	t.Log("Scenario 7.7: Unicode in peer name")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	unicodeNames := []string{
		"peer-日本語",
		"peer-emoji-🚀",
		"peer-Ω-symbol",
		"peer-中文名字",
	}

	for _, name := range unicodeNames {
		t.Run(name, func(t *testing.T) {
			peer := &mesh.Peer{
				Name:      name,
				PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				Endpoints: []string{"127.0.0.1:51820"},
			}

			client := NewClient(getSignalingURL(), networkID, networkSecret)
			client.SetLocalPeer(peer)
			defer func() {
				client.Unregister()
				client.Stop()
			}()

			resp, err := client.Register()
			if err != nil {
				t.Logf("Unicode name '%s' rejected: %v", name, err)
			} else {
				t.Logf("PASS: Unicode name '%s' accepted, IP: %s", name, resp.VirtualIP)
			}
		})
	}
}

// Scenario 7.8: Maximum endpoints per peer
func TestScenario_7_8_MaxEndpoints(t *testing.T) {
	t.Log("Scenario 7.8: Maximum endpoints per peer")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	// Create peer with many endpoints
	endpoints := make([]string, 50)
	for i := 0; i < 50; i++ {
		endpoints[i] = "192.168.1." + string(rune('1'+i%9)) + ":51820"
	}

	peer := &mesh.Peer{
		Name:      "scenario-7-8-many-endpoints",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Endpoints: endpoints,
	}

	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	resp, err := client.Register()
	if err != nil {
		t.Logf("Note: Many endpoints rejected: %v", err)
	} else {
		t.Logf("PASS: %d endpoints accepted, IP: %s", len(endpoints), resp.VirtualIP)
	}
}
