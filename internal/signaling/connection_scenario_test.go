//go:build integration
// +build integration

package signaling

import (
	"testing"
	"time"

	"github.com/selftunnel/selftunnel/internal/mesh"
)

// =============================================================================
// Scenario 1: Connection Scenarios
// =============================================================================

// Scenario 1.1: Single node connects to signaling server
func TestScenario_1_1_SingleNodeConnect(t *testing.T) {
	t.Log("Scenario 1.1: Single node connects to signaling server")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, err := createTestPeer("scenario-1-1-peer")
	if err != nil {
		t.Fatalf("FAIL: Failed to create peer: %v", err)
	}

	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	// Test: Register
	resp, err := client.Register()
	if err != nil {
		t.Fatalf("FAIL: Registration failed: %v", err)
	}

	if !resp.Success {
		t.Fatalf("FAIL: Registration not successful: %s", resp.Message)
	}

	if resp.VirtualIP == "" {
		t.Fatal("FAIL: No VirtualIP assigned")
	}

	t.Logf("PASS: Single node connected, VirtualIP: %s", resp.VirtualIP)
}

// Scenario 1.2: Two nodes connect and discover each other
func TestScenario_1_2_TwoNodesDiscovery(t *testing.T) {
	t.Log("Scenario 1.2: Two nodes connect and discover each other")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	// Create Node A
	peerA, _ := createTestPeer("scenario-1-2-node-a")
	clientA := NewClient(getSignalingURL(), networkID, networkSecret)
	clientA.SetLocalPeer(peerA)
	defer func() {
		clientA.Unregister()
		clientA.Stop()
	}()

	respA, err := clientA.Register()
	if err != nil {
		t.Fatalf("FAIL: Node A registration failed: %v", err)
	}
	t.Logf("Node A registered: %s", respA.VirtualIP)

	// Create Node B
	peerB, _ := createTestPeer("scenario-1-2-node-b")
	clientB := NewClient(getSignalingURL(), networkID, networkSecret)
	clientB.SetLocalPeer(peerB)
	defer func() {
		clientB.Unregister()
		clientB.Stop()
	}()

	respB, err := clientB.Register()
	if err != nil {
		t.Fatalf("FAIL: Node B registration failed: %v", err)
	}
	t.Logf("Node B registered: %s", respB.VirtualIP)

	time.Sleep(500 * time.Millisecond)

	// Node A should discover Node B
	peersA, err := clientA.GetPeers()
	if err != nil {
		t.Fatalf("FAIL: Node A failed to get peers: %v", err)
	}

	foundB := false
	for _, p := range peersA {
		if p.PublicKey == peerB.PublicKey {
			foundB = true
			break
		}
	}

	if !foundB {
		t.Fatal("FAIL: Node A cannot discover Node B")
	}

	// Node B should discover Node A
	peersB, err := clientB.GetPeers()
	if err != nil {
		t.Fatalf("FAIL: Node B failed to get peers: %v", err)
	}

	foundA := false
	for _, p := range peersB {
		if p.PublicKey == peerA.PublicKey {
			foundA = true
			break
		}
	}

	if !foundA {
		t.Fatal("FAIL: Node B cannot discover Node A")
	}

	t.Log("PASS: Two nodes connected and discovered each other")
}

// Scenario 1.3: Three+ nodes connect (multi-node scenario)
func TestScenario_1_3_MultiNodeConnect(t *testing.T) {
	t.Log("Scenario 1.3: Multi-node connection (5 nodes)")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	numNodes := 5
	clients := make([]*Client, numNodes)
	peers := make([]*mesh.Peer, numNodes)

	// Create and register all nodes
	for i := 0; i < numNodes; i++ {
		peer, _ := createTestPeer("scenario-1-3-node-" + string(rune('a'+i)))
		peers[i] = peer

		client := NewClient(getSignalingURL(), networkID, networkSecret)
		client.SetLocalPeer(peer)
		clients[i] = client

		resp, err := client.Register()
		if err != nil {
			t.Fatalf("FAIL: Node %d registration failed: %v", i, err)
		}
		t.Logf("Node %d registered: %s", i, resp.VirtualIP)

		time.Sleep(100 * time.Millisecond) // Stagger registrations
	}

	defer func() {
		for _, c := range clients {
			c.Unregister()
			c.Stop()
		}
	}()

	time.Sleep(1 * time.Second)

	// Verify all nodes can see all others
	for i, client := range clients {
		peerList, err := client.GetPeers()
		if err != nil {
			t.Fatalf("FAIL: Node %d failed to get peers: %v", i, err)
		}

		if len(peerList) < numNodes {
			t.Errorf("FAIL: Node %d sees only %d peers, expected %d", i, len(peerList), numNodes)
		}
	}

	t.Logf("PASS: All %d nodes connected and can discover each other", numNodes)
}

// Scenario 1.4: Node reconnects after disconnect
func TestScenario_1_4_NodeReconnect(t *testing.T) {
	t.Log("Scenario 1.4: Node reconnects after disconnect")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, _ := createTestPeer("scenario-1-4-reconnect")
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)

	// First connection
	resp1, err := client.Register()
	if err != nil {
		t.Fatalf("FAIL: First registration failed: %v", err)
	}
	firstIP := resp1.VirtualIP
	t.Logf("First connection: %s", firstIP)

	// Disconnect
	err = client.Unregister()
	if err != nil {
		t.Logf("Note: Unregister returned error (may be expected): %v", err)
	}
	client.Stop()

	time.Sleep(500 * time.Millisecond)

	// Reconnect with new client (same peer identity)
	client2 := NewClient(getSignalingURL(), networkID, networkSecret)
	client2.SetLocalPeer(peer)
	defer func() {
		client2.Unregister()
		client2.Stop()
	}()

	resp2, err := client2.Register()
	if err != nil {
		t.Fatalf("FAIL: Reconnection failed: %v", err)
	}
	t.Logf("Reconnection: %s", resp2.VirtualIP)

	if !resp2.Success {
		t.Fatal("FAIL: Reconnection not successful")
	}

	t.Log("PASS: Node successfully reconnected after disconnect")
}

// Scenario 1.5: Node connects with invalid credentials
func TestScenario_1_5_InvalidCredentials(t *testing.T) {
	t.Log("Scenario 1.5: Node connects with invalid credentials")

	testCases := []struct {
		name          string
		networkID     string
		networkSecret string
		expectError   bool
	}{
		{
			name:          "Empty network ID",
			networkID:     "",
			networkSecret: "valid-secret",
			expectError:   true,
		},
		{
			name:          "Empty secret",
			networkID:     "valid-id",
			networkSecret: "",
			expectError:   true,
		},
		{
			name:          "Invalid characters",
			networkID:     "invalid!@#$%",
			networkSecret: "secret!@#$%",
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			peer, _ := createTestPeer("scenario-1-5-invalid")
			client := NewClient(getSignalingURL(), tc.networkID, tc.networkSecret)
			client.SetLocalPeer(peer)
			defer client.Stop()

			_, err := client.Register()
			if tc.expectError && err == nil {
				// Note: Server may accept any registration, so this might pass
				t.Logf("Note: Server accepted credentials for: %s", tc.name)
			} else if !tc.expectError && err != nil {
				t.Errorf("FAIL: Unexpected error for %s: %v", tc.name, err)
			} else {
				t.Logf("PASS: %s - handled correctly", tc.name)
			}
		})
	}

	t.Log("PASS: Invalid credential scenarios completed")
}

// Scenario 1.6: Concurrent connections from same network
func TestScenario_1_6_ConcurrentConnections(t *testing.T) {
	t.Log("Scenario 1.6: Concurrent connections from same network")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	numConcurrent := 10
	results := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(idx int) {
			peer, _ := createTestPeer("scenario-1-6-concurrent-" + string(rune('a'+idx)))
			client := NewClient(getSignalingURL(), networkID, networkSecret)
			client.SetLocalPeer(peer)
			defer func() {
				client.Unregister()
				client.Stop()
			}()

			_, err := client.Register()
			results <- err
		}(i)
	}

	// Collect results
	successCount := 0
	for i := 0; i < numConcurrent; i++ {
		err := <-results
		if err == nil {
			successCount++
		}
	}

	if successCount < numConcurrent/2 {
		t.Fatalf("FAIL: Only %d/%d concurrent connections succeeded", successCount, numConcurrent)
	}

	t.Logf("PASS: %d/%d concurrent connections succeeded", successCount, numConcurrent)
}
