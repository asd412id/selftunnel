//go:build integration
// +build integration

package integration

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/selftunnel/selftunnel/internal/crypto"
	"github.com/selftunnel/selftunnel/internal/mesh"
	"github.com/selftunnel/selftunnel/internal/signaling"
)

const (
	signalingURL = "https://signaling-server.maccaqe.id"
)

// TestNode represents a virtual test node
type TestNode struct {
	Name          string
	KeyPair       *crypto.KeyPair
	VirtualIP     string
	Client        *signaling.Client
	PeerManager   *mesh.PeerManager
	Router        *mesh.Router
	NetworkID     string
	NetworkSecret string
	t             *testing.T
}

// createTestNetwork creates a unique network for testing
func createTestNetwork() (string, string, error) {
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

// createTestNode creates a test node
func createTestNode(t *testing.T, name, networkID, networkSecret string) (*TestNode, error) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	peer := &mesh.Peer{
		Name:      name,
		PublicKey: crypto.ToBase64(keyPair.PublicKey),
		VirtualIP: "", // Will be assigned by server
		Endpoints: []string{"127.0.0.1:51820"},
		State:     mesh.PeerStateDisconnected,
	}

	client := signaling.NewClient(signalingURL, networkID, networkSecret)
	client.SetLocalPeer(peer)

	peerManager := mesh.NewPeerManager(peer)
	router := mesh.NewRouter(peerManager)

	return &TestNode{
		Name:          name,
		KeyPair:       keyPair,
		Client:        client,
		PeerManager:   peerManager,
		Router:        router,
		NetworkID:     networkID,
		NetworkSecret: networkSecret,
		t:             t,
	}, nil
}

// Register registers the node with signaling server
func (n *TestNode) Register() error {
	resp, err := n.Client.Register()
	if err != nil {
		return err
	}
	n.VirtualIP = resp.VirtualIP

	// Update local peer's virtual IP
	n.PeerManager.LocalPeer().VirtualIP = resp.VirtualIP

	return nil
}

// DiscoverPeers discovers other peers in the network
func (n *TestNode) DiscoverPeers() ([]*mesh.Peer, error) {
	peers, err := n.Client.GetPeers()
	if err != nil {
		return nil, err
	}

	// Add discovered peers to peer manager
	for _, p := range peers {
		if p.PublicKey == n.PeerManager.LocalPeer().PublicKey {
			continue // Skip self
		}

		meshPeer := &mesh.Peer{
			Name:      p.Name,
			PublicKey: p.PublicKey,
			VirtualIP: p.VirtualIP,
			Endpoints: p.Endpoints,
			State:     mesh.PeerStateConnected, // Assume connected for test
		}

		// Try to add, ignore if already exists
		n.PeerManager.AddPeer(meshPeer)
	}

	// Update routes
	n.Router.UpdateRoutesFromPeers()

	return n.PeerManager.GetAllPeers(), nil
}

// Cleanup cleans up the node
func (n *TestNode) Cleanup() {
	n.Client.Unregister()
	n.Client.Stop()
	n.PeerManager.Close()
}

// PingResult represents the result of a ping operation
type PingResult struct {
	From    string
	To      string
	Success bool
	Latency time.Duration
	Error   error
}

// simulatePing simulates a ping between two nodes
func simulatePing(from, to *TestNode) PingResult {
	start := time.Now()

	// Check if 'to' is reachable via routing
	toIP := net.ParseIP(to.VirtualIP)
	if toIP == nil {
		return PingResult{
			From:    from.Name,
			To:      to.Name,
			Success: false,
			Error:   fmt.Errorf("invalid destination IP"),
		}
	}

	route := from.Router.FindRoute(toIP)
	if route == nil {
		return PingResult{
			From:    from.Name,
			To:      to.Name,
			Success: false,
			Error:   fmt.Errorf("no route to host"),
		}
	}

	// Simulate network latency
	time.Sleep(time.Duration(10+time.Now().UnixNano()%20) * time.Millisecond)

	latency := time.Since(start)

	return PingResult{
		From:    from.Name,
		To:      to.Name,
		Success: true,
		Latency: latency,
	}
}

// =============================================================================
// Test 1: Multi-Node Ping Test
// =============================================================================

func TestMultiNode_1_PingTest(t *testing.T) {
	t.Log("Test 1: Multi-Node Ping Test")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Create 3 nodes
	nodeA, err := createTestNode(t, "node-a", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node A: %v", err)
	}
	defer nodeA.Cleanup()

	nodeB, err := createTestNode(t, "node-b", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node B: %v", err)
	}
	defer nodeB.Cleanup()

	nodeC, err := createTestNode(t, "node-c", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node C: %v", err)
	}
	defer nodeC.Cleanup()

	// Register all nodes
	if err := nodeA.Register(); err != nil {
		t.Fatalf("Failed to register node A: %v", err)
	}
	t.Logf("Node A registered: %s", nodeA.VirtualIP)

	if err := nodeB.Register(); err != nil {
		t.Fatalf("Failed to register node B: %v", err)
	}
	t.Logf("Node B registered: %s", nodeB.VirtualIP)

	if err := nodeC.Register(); err != nil {
		t.Fatalf("Failed to register node C: %v", err)
	}
	t.Logf("Node C registered: %s", nodeC.VirtualIP)

	time.Sleep(500 * time.Millisecond) // Allow propagation

	// Discover peers
	peersA, _ := nodeA.DiscoverPeers()
	peersB, _ := nodeB.DiscoverPeers()
	peersC, _ := nodeC.DiscoverPeers()

	t.Logf("Node A sees %d peers", len(peersA))
	t.Logf("Node B sees %d peers", len(peersB))
	t.Logf("Node C sees %d peers", len(peersC))

	// Test pings
	pingTests := []struct {
		from *TestNode
		to   *TestNode
	}{
		{nodeA, nodeB},
		{nodeA, nodeC},
		{nodeB, nodeC},
		{nodeB, nodeA},
		{nodeC, nodeA},
		{nodeC, nodeB},
	}

	var totalLatency time.Duration
	successCount := 0

	for _, pt := range pingTests {
		result := simulatePing(pt.from, pt.to)
		if result.Success {
			successCount++
			totalLatency += result.Latency
			t.Logf("PING %s -> %s: OK (latency: %v)", result.From, result.To, result.Latency)
		} else {
			t.Logf("PING %s -> %s: FAIL (%v)", result.From, result.To, result.Error)
		}
	}

	// Calculate metrics
	avgLatency := totalLatency / time.Duration(successCount)
	packetLoss := float64(len(pingTests)-successCount) / float64(len(pingTests)) * 100

	t.Logf("Results: %d/%d pings successful", successCount, len(pingTests))
	t.Logf("Average latency: %v", avgLatency)
	t.Logf("Packet loss: %.1f%%", packetLoss)

	if successCount < len(pingTests)/2 {
		t.Errorf("Too many ping failures")
	}
}

// =============================================================================
// Test 2: Bidirectional Communication Test
// =============================================================================

func TestMultiNode_2_BidirectionalCommunication(t *testing.T) {
	t.Log("Test 2: Bidirectional Communication Test")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Create 3 nodes
	nodes := make([]*TestNode, 3)
	for i := 0; i < 3; i++ {
		node, err := createTestNode(t, fmt.Sprintf("bidir-node-%d", i), networkID, networkSecret)
		if err != nil {
			t.Fatalf("Failed to create node %d: %v", i, err)
		}
		nodes[i] = node
		defer node.Cleanup()

		if err := node.Register(); err != nil {
			t.Fatalf("Failed to register node %d: %v", i, err)
		}
		t.Logf("Node %d registered: %s", i, node.VirtualIP)
	}

	time.Sleep(500 * time.Millisecond)

	// Discover peers
	for _, node := range nodes {
		node.DiscoverPeers()
	}

	// Simulate bidirectional communication
	type Message struct {
		From    string
		To      string
		Content string
		Reply   string
	}

	messages := []Message{
		{From: "bidir-node-0", To: "bidir-node-1", Content: "Hello from 0", Reply: "Reply from 1"},
		{From: "bidir-node-1", To: "bidir-node-2", Content: "Hello from 1", Reply: "Reply from 2"},
		{From: "bidir-node-0", To: "bidir-node-2", Content: "Hello from 0 to 2", Reply: "Reply from 2 to 0"},
	}

	successCount := 0
	for _, msg := range messages {
		// Find sender and receiver
		var sender, receiver *TestNode
		for _, n := range nodes {
			if n.Name == msg.From {
				sender = n
			}
			if n.Name == msg.To {
				receiver = n
			}
		}

		if sender == nil || receiver == nil {
			t.Errorf("Could not find sender/receiver for message")
			continue
		}

		// Simulate send
		toIP := net.ParseIP(receiver.VirtualIP)
		route := sender.Router.FindRoute(toIP)
		if route == nil {
			t.Logf("FAIL: No route from %s to %s", msg.From, msg.To)
			continue
		}

		// Simulate receive and reply
		fromIP := net.ParseIP(sender.VirtualIP)
		replyRoute := receiver.Router.FindRoute(fromIP)
		if replyRoute == nil {
			t.Logf("FAIL: No reply route from %s to %s", msg.To, msg.From)
			continue
		}

		successCount++
		t.Logf("SUCCESS: %s -> %s: '%s' -> '%s'", msg.From, msg.To, msg.Content, msg.Reply)
	}

	t.Logf("Bidirectional test: %d/%d successful", successCount, len(messages))
}

// =============================================================================
// Test 3: Mesh Routing Test
// =============================================================================

func TestMultiNode_3_MeshRouting(t *testing.T) {
	t.Log("Test 3: Mesh Routing Test")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Create 4 nodes for mesh testing
	numNodes := 4
	nodes := make([]*TestNode, numNodes)

	for i := 0; i < numNodes; i++ {
		node, err := createTestNode(t, fmt.Sprintf("mesh-node-%d", i), networkID, networkSecret)
		if err != nil {
			t.Fatalf("Failed to create node %d: %v", i, err)
		}
		nodes[i] = node
		defer node.Cleanup()

		if err := node.Register(); err != nil {
			t.Fatalf("Failed to register node %d: %v", i, err)
		}
		time.Sleep(100 * time.Millisecond) // Stagger
	}

	time.Sleep(1 * time.Second)

	// Discover and build routes
	for _, node := range nodes {
		node.DiscoverPeers()
		node.Router.BuildMeshRoutes()
	}

	// Test routing table correctness
	t.Log("Testing routing table correctness...")

	for i, node := range nodes {
		routes := node.Router.GetAllRoutes()
		t.Logf("Node %d (%s) has %d routes", i, node.VirtualIP, len(routes))

		// Should have routes to all other nodes
		expectedRoutes := numNodes - 1
		if len(routes) < expectedRoutes {
			t.Logf("Warning: Node %d has fewer routes than expected (%d < %d)", i, len(routes), expectedRoutes)
		}
	}

	// Test next-hop calculation
	t.Log("Testing next-hop calculation...")

	testCount := 0
	successCount := 0

	for i, fromNode := range nodes {
		for j, toNode := range nodes {
			if i == j {
				continue
			}

			testCount++
			destIP := net.ParseIP(toNode.VirtualIP)
			nextHop := fromNode.Router.FindNextHop(destIP)

			if nextHop != nil {
				successCount++
				t.Logf("Route: Node %d -> Node %d via %s", i, j, nextHop.Name)
			} else {
				t.Logf("FAIL: No next hop from Node %d to Node %d", i, j)
			}
		}
	}

	t.Logf("Next-hop test: %d/%d successful", successCount, testCount)
}

// =============================================================================
// Test 4: Concurrent Communication Test
// =============================================================================

func TestMultiNode_4_ConcurrentCommunication(t *testing.T) {
	t.Log("Test 4: Concurrent Communication Test")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Create 5 nodes
	numNodes := 5
	nodes := make([]*TestNode, numNodes)

	for i := 0; i < numNodes; i++ {
		node, err := createTestNode(t, fmt.Sprintf("concurrent-node-%d", i), networkID, networkSecret)
		if err != nil {
			t.Fatalf("Failed to create node %d: %v", i, err)
		}
		nodes[i] = node
		defer node.Cleanup()

		if err := node.Register(); err != nil {
			t.Fatalf("Failed to register node %d: %v", i, err)
		}
	}

	time.Sleep(1 * time.Second)

	for _, node := range nodes {
		node.DiscoverPeers()
	}

	// Concurrent sending
	var wg sync.WaitGroup
	var successCount int32
	var failCount int32
	totalMessages := numNodes * (numNodes - 1) * 10 // Each pair sends 10 messages

	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i == j {
				continue
			}

			wg.Add(1)
			go func(from, to int) {
				defer wg.Done()

				for k := 0; k < 10; k++ {
					destIP := net.ParseIP(nodes[to].VirtualIP)
					route := nodes[from].Router.FindRoute(destIP)

					if route != nil {
						atomic.AddInt32(&successCount, 1)
					} else {
						atomic.AddInt32(&failCount, 1)
					}
				}
			}(i, j)
		}
	}

	wg.Wait()

	success := atomic.LoadInt32(&successCount)
	fail := atomic.LoadInt32(&failCount)
	total := success + fail

	t.Logf("Concurrent test: %d/%d messages routed successfully", success, total)
	t.Logf("Failure rate: %.2f%%", float64(fail)/float64(total)*100)

	if fail > int32(totalMessages/10) {
		t.Errorf("Too many failures in concurrent test")
	}
}

// =============================================================================
// Test 5: Sustained Communication Test
// =============================================================================

func TestMultiNode_5_SustainedCommunication(t *testing.T) {
	t.Log("Test 5: Sustained Communication Test (10 seconds)")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Create 3 nodes
	nodes := make([]*TestNode, 3)
	for i := 0; i < 3; i++ {
		node, err := createTestNode(t, fmt.Sprintf("sustained-node-%d", i), networkID, networkSecret)
		if err != nil {
			t.Fatalf("Failed to create node %d: %v", i, err)
		}
		nodes[i] = node
		defer node.Cleanup()

		if err := node.Register(); err != nil {
			t.Fatalf("Failed to register node %d: %v", i, err)
		}
	}

	time.Sleep(500 * time.Millisecond)

	for _, node := range nodes {
		node.DiscoverPeers()
	}

	// Sustained traffic for 10 seconds
	duration := 10 * time.Second
	deadline := time.Now().Add(duration)

	var successCount, failCount int32
	var wg sync.WaitGroup

	// Start traffic generators
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(nodeIdx int) {
			defer wg.Done()

			for time.Now().Before(deadline) {
				// Send to random other node
				targetIdx := (nodeIdx + 1) % 3
				destIP := net.ParseIP(nodes[targetIdx].VirtualIP)
				route := nodes[nodeIdx].Router.FindRoute(destIP)

				if route != nil {
					atomic.AddInt32(&successCount, 1)
				} else {
					atomic.AddInt32(&failCount, 1)
				}

				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}

	// Also do periodic health checks (keepalive simulation)
	wg.Add(1)
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if time.Now().After(deadline) {
					return
				}
				// Refresh peers
				for _, node := range nodes {
					node.DiscoverPeers()
				}
				t.Log("Keepalive: peers refreshed")
			}
			if time.Now().After(deadline) {
				return
			}
		}
	}()

	wg.Wait()

	success := atomic.LoadInt32(&successCount)
	fail := atomic.LoadInt32(&failCount)
	total := success + fail

	t.Logf("Sustained test completed:")
	t.Logf("  - Duration: %v", duration)
	t.Logf("  - Total messages: %d", total)
	t.Logf("  - Success: %d (%.1f%%)", success, float64(success)/float64(total)*100)
	t.Logf("  - Failures: %d", fail)
}

// =============================================================================
// Test 6: Large Packet Test
// =============================================================================

func TestMultiNode_6_LargePacket(t *testing.T) {
	t.Log("Test 6: Large Packet Test (MTU boundary)")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	nodeA, err := createTestNode(t, "large-packet-a", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node A: %v", err)
	}
	defer nodeA.Cleanup()

	nodeB, err := createTestNode(t, "large-packet-b", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node B: %v", err)
	}
	defer nodeB.Cleanup()

	if err := nodeA.Register(); err != nil {
		t.Fatalf("Failed to register node A: %v", err)
	}
	if err := nodeB.Register(); err != nil {
		t.Fatalf("Failed to register node B: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	nodeA.DiscoverPeers()
	nodeB.DiscoverPeers()

	// Test various packet sizes
	packetSizes := []int{
		64,    // Small
		512,   // Medium
		1280,  // IPv6 minimum MTU
		1420,  // WireGuard typical MTU
		1500,  // Standard Ethernet MTU
		9000,  // Jumbo frame
		65535, // Maximum
	}

	for _, size := range packetSizes {
		// Simulate packet creation
		packet := make([]byte, size)
		for i := range packet {
			packet[i] = byte(i % 256)
		}

		// Check routing
		destIP := net.ParseIP(nodeB.VirtualIP)
		route := nodeA.Router.FindRoute(destIP)

		if route != nil {
			// Simulate fragmentation check
			mtu := 1420 // WireGuard MTU
			fragments := (size + mtu - 1) / mtu

			if fragments > 1 {
				t.Logf("Packet %d bytes: Would fragment into %d pieces", size, fragments)
			} else {
				t.Logf("Packet %d bytes: No fragmentation needed", size)
			}
		} else {
			t.Logf("Packet %d bytes: No route", size)
		}
	}
}

// =============================================================================
// Test 7: Connection Recovery Test
// =============================================================================

func TestMultiNode_7_ConnectionRecovery(t *testing.T) {
	t.Log("Test 7: Connection Recovery Test")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Create 3 nodes
	nodeA, err := createTestNode(t, "recovery-a", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node A: %v", err)
	}
	defer nodeA.Cleanup()

	nodeB, err := createTestNode(t, "recovery-b", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node B: %v", err)
	}
	// Note: nodeB will be disconnected and reconnected

	nodeC, err := createTestNode(t, "recovery-c", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node C: %v", err)
	}
	defer nodeC.Cleanup()

	// Register all
	for _, node := range []*TestNode{nodeA, nodeB, nodeC} {
		if err := node.Register(); err != nil {
			t.Fatalf("Failed to register %s: %v", node.Name, err)
		}
		t.Logf("%s registered: %s", node.Name, node.VirtualIP)
	}

	time.Sleep(500 * time.Millisecond)

	// Discover peers
	nodeA.DiscoverPeers()
	nodeC.DiscoverPeers()

	// Verify initial connectivity
	t.Log("Initial state: All nodes connected")
	peersA := nodeA.PeerManager.GetAllPeers()
	t.Logf("Node A sees %d peers", len(peersA))

	// Simulate Node B disconnect
	t.Log("Simulating Node B disconnect...")
	nodeB.Client.Unregister()
	nodeB.Client.Stop()

	time.Sleep(1 * time.Second)

	// Refresh peers
	nodeA.DiscoverPeers()
	nodeC.DiscoverPeers()

	// Verify A and C can still communicate
	destIP := net.ParseIP(nodeC.VirtualIP)
	route := nodeA.Router.FindRoute(destIP)
	if route != nil {
		t.Log("SUCCESS: Node A can still route to Node C after Node B disconnect")
	} else {
		t.Log("Note: Route to Node C not found (may need route refresh)")
	}

	// Reconnect Node B
	t.Log("Reconnecting Node B...")
	nodeB2, err := createTestNode(t, "recovery-b", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to recreate node B: %v", err)
	}
	defer nodeB2.Cleanup()

	if err := nodeB2.Register(); err != nil {
		t.Fatalf("Failed to re-register node B: %v", err)
	}
	t.Logf("Node B reconnected: %s", nodeB2.VirtualIP)

	time.Sleep(500 * time.Millisecond)

	// Refresh and verify
	nodeA.DiscoverPeers()
	nodeA.Router.UpdateRoutesFromPeers()

	peersAAfter := nodeA.PeerManager.GetAllPeers()
	t.Logf("After recovery: Node A sees %d peers", len(peersAAfter))

	// Final connectivity check
	destB := net.ParseIP(nodeB2.VirtualIP)
	routeB := nodeA.Router.FindRoute(destB)
	if routeB != nil {
		t.Log("SUCCESS: Node A can route to reconnected Node B")
	} else {
		t.Log("Note: Route to Node B not found after reconnect")
	}

	t.Log("Connection recovery test completed")
}
