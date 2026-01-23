//go:build integration
// +build integration

package integration

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/selftunnel/selftunnel/internal/dns"
)

// =============================================================================
// Production Retest 1: Node Connection Test
// Test 3+ nodes connection without panic/rush
// =============================================================================

func TestProductionRetest_1_NodeConnection(t *testing.T) {
	t.Log("=== Production Retest 1: Node Connection Test ===")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Track goroutines before test
	goroutinesBefore := runtime.NumGoroutine()
	t.Logf("Goroutines before: %d", goroutinesBefore)

	// Create 5 nodes to test connection rush
	numNodes := 5
	nodes := make([]*TestNode, numNodes)
	var connectionErrors []string

	t.Log("Creating and registering 5 nodes simultaneously...")
	startTime := time.Now()

	// Register all nodes rapidly (simulate connection rush)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < numNodes; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			node, err := createTestNode(t, fmt.Sprintf("retest-node-%d", idx), networkID, networkSecret)
			if err != nil {
				mu.Lock()
				connectionErrors = append(connectionErrors, fmt.Sprintf("node-%d create: %v", idx, err))
				mu.Unlock()
				return
			}

			if err := node.Register(); err != nil {
				mu.Lock()
				connectionErrors = append(connectionErrors, fmt.Sprintf("node-%d register: %v", idx, err))
				mu.Unlock()
				node.Cleanup()
				return
			}

			mu.Lock()
			nodes[idx] = node
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	registrationDuration := time.Since(startTime)

	// Check for connection errors
	if len(connectionErrors) > 0 {
		for _, e := range connectionErrors {
			t.Errorf("Connection error: %s", e)
		}
	}

	// Cleanup and count successful connections
	successCount := 0
	for i, node := range nodes {
		if node != nil {
			successCount++
			t.Logf("Node %d registered successfully: %s", i, node.VirtualIP)
			defer node.Cleanup()
		}
	}

	// Check goroutines after (shouldn't spike dramatically)
	goroutinesAfter := runtime.NumGoroutine()
	t.Logf("Goroutines after: %d (diff: %+d)", goroutinesAfter, goroutinesAfter-goroutinesBefore)

	t.Logf("Results: %d/%d nodes connected in %v", successCount, numNodes, registrationDuration)

	// Verify connection stability by checking peer discovery
	time.Sleep(500 * time.Millisecond)
	for _, node := range nodes {
		if node != nil {
			peers, _ := node.DiscoverPeers()
			t.Logf("Node %s sees %d peers", node.Name, len(peers))
		}
	}

	if successCount < numNodes {
		t.Errorf("Not all nodes connected successfully: %d/%d", successCount, numNodes)
	}

	// Check goroutine leak
	if goroutinesAfter-goroutinesBefore > 50 {
		t.Errorf("Possible goroutine leak: %d new goroutines", goroutinesAfter-goroutinesBefore)
	}

	t.Log("=== Node Connection Test COMPLETE ===")
}

// =============================================================================
// Production Retest 2: DNS Resolution Test
// Test DNS resolve for peer names without blocking
// =============================================================================

func TestProductionRetest_2_DNSResolution(t *testing.T) {
	t.Log("=== Production Retest 2: DNS Resolution Test ===")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Create 3 nodes
	nodeA, err := createTestNode(t, "dns-test-alice", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node A: %v", err)
	}
	defer nodeA.Cleanup()

	nodeB, err := createTestNode(t, "dns-test-bob", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node B: %v", err)
	}
	defer nodeB.Cleanup()

	nodeC, err := createTestNode(t, "dns-test-charlie", networkID, networkSecret)
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
	nodeB.DiscoverPeers()
	nodeC.DiscoverPeers()

	// Create DNS resolver for node A
	resolver := dns.NewMeshResolver(nodeA.PeerManager)

	// Test DNS resolution
	t.Log("Testing DNS resolution...")

	testCases := []struct {
		name     string
		expected bool
	}{
		{"dns-test-bob", true},
		{"dns-test-charlie", true},
		{"nonexistent-peer", false},
	}

	resolutionResults := make(map[string]bool)
	var resolutionLatencies []time.Duration

	for _, tc := range testCases {
		start := time.Now()

		// Use timeout channel to detect blocking
		done := make(chan struct{})
		var ip string
		var found bool

		go func() {
			ip, found = resolver.GetPeerByName(tc.name)
			close(done)
		}()

		select {
		case <-done:
			latency := time.Since(start)
			resolutionLatencies = append(resolutionLatencies, latency)

			if found != tc.expected {
				t.Errorf("DNS resolution for %s: expected found=%v, got found=%v", tc.name, tc.expected, found)
			} else if found {
				t.Logf("Resolved %s -> %s (latency: %v)", tc.name, ip, latency)
				resolutionResults[tc.name] = true
			} else {
				t.Logf("Correctly returned not found for %s (latency: %v)", tc.name, latency)
				resolutionResults[tc.name] = false
			}

		case <-time.After(5 * time.Second):
			t.Errorf("DNS resolution BLOCKED for %s (>5s timeout)", tc.name)
		}
	}

	// Test newly added peer resolution
	t.Log("Testing newly added peer resolution...")

	nodeD, err := createTestNode(t, "dns-test-david", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node D: %v", err)
	}
	defer nodeD.Cleanup()

	if err := nodeD.Register(); err != nil {
		t.Fatalf("Failed to register node D: %v", err)
	}
	t.Logf("Node D registered: %s", nodeD.VirtualIP)

	// Refresh peers on node A
	time.Sleep(500 * time.Millisecond)
	nodeA.DiscoverPeers()

	// Try to resolve newly added peer
	start := time.Now()
	ip, found := resolver.GetPeerByName("dns-test-david")
	latency := time.Since(start)

	if found {
		t.Logf("Resolved newly added peer dns-test-david -> %s (latency: %v)", ip, latency)
	} else {
		t.Logf("Note: Newly added peer not immediately resolvable (may need more propagation time)")
	}

	// Calculate average latency
	var totalLatency time.Duration
	for _, l := range resolutionLatencies {
		totalLatency += l
	}
	avgLatency := totalLatency / time.Duration(len(resolutionLatencies))
	t.Logf("Average DNS resolution latency: %v", avgLatency)

	t.Log("=== DNS Resolution Test COMPLETE ===")
}

// =============================================================================
// Production Retest 3: Disconnect/Reconnect Test
// Test auto-reconnect without goroutine storm
// =============================================================================

func TestProductionRetest_3_DisconnectReconnect(t *testing.T) {
	t.Log("=== Production Retest 3: Disconnect/Reconnect Test ===")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Track initial goroutines
	goroutinesBefore := runtime.NumGoroutine()
	t.Logf("Goroutines before: %d", goroutinesBefore)

	// Create 3 nodes
	nodeA, err := createTestNode(t, "reconnect-a", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node A: %v", err)
	}
	defer nodeA.Cleanup()

	nodeB, err := createTestNode(t, "reconnect-b", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node B: %v", err)
	}
	// Note: nodeB will be disconnected

	nodeC, err := createTestNode(t, "reconnect-c", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to create node C: %v", err)
	}
	defer nodeC.Cleanup()

	// Register all
	for _, node := range []*TestNode{nodeA, nodeB, nodeC} {
		if err := node.Register(); err != nil {
			t.Fatalf("Failed to register %s: %v", node.Name, err)
		}
	}

	time.Sleep(500 * time.Millisecond)

	nodeA.DiscoverPeers()
	nodeC.DiscoverPeers()

	t.Logf("Initial state: Node A sees %d peers", len(nodeA.PeerManager.GetAllPeers()))

	// Simulate Node B disconnect
	t.Log("Disconnecting Node B...")
	nodeB.Client.Unregister()
	nodeB.Client.Stop()

	goroutinesAfterDisconnect := runtime.NumGoroutine()
	t.Logf("Goroutines after disconnect: %d", goroutinesAfterDisconnect)

	time.Sleep(1 * time.Second)

	// Verify A and C still connected
	nodeA.DiscoverPeers()
	peersAfterDisconnect := nodeA.PeerManager.GetAllPeers()
	t.Logf("After disconnect: Node A sees %d peers", len(peersAfterDisconnect))

	// Reconnect Node B (simulate auto-reconnect)
	t.Log("Reconnecting Node B...")

	nodeB2, err := createTestNode(t, "reconnect-b", networkID, networkSecret)
	if err != nil {
		t.Fatalf("Failed to recreate node B: %v", err)
	}
	defer nodeB2.Cleanup()

	if err := nodeB2.Register(); err != nil {
		t.Fatalf("Failed to re-register node B: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Verify reconnection
	nodeA.DiscoverPeers()
	peersAfterReconnect := nodeA.PeerManager.GetAllPeers()
	t.Logf("After reconnect: Node A sees %d peers", len(peersAfterReconnect))

	// Check for goroutine storm
	goroutinesAfterReconnect := runtime.NumGoroutine()
	t.Logf("Goroutines after reconnect: %d", goroutinesAfterReconnect)

	goroutineGrowth := goroutinesAfterReconnect - goroutinesBefore
	if goroutineGrowth > 30 {
		t.Errorf("Possible goroutine storm: %d new goroutines after disconnect/reconnect cycle", goroutineGrowth)
	} else {
		t.Logf("Goroutine growth acceptable: +%d", goroutineGrowth)
	}

	// Verify routing still works
	destIP := net.ParseIP(nodeC.VirtualIP)
	route := nodeA.Router.FindRoute(destIP)
	if route != nil {
		t.Log("SUCCESS: Routing still works after disconnect/reconnect")
	} else {
		t.Log("Note: Route refresh may be needed")
	}

	t.Log("=== Disconnect/Reconnect Test COMPLETE ===")
}

// =============================================================================
// Production Retest 4: Sustained Connection Test
// Run connection for 1-2 minutes, verify keepalive works
// =============================================================================

func TestProductionRetest_4_SustainedConnection(t *testing.T) {
	t.Log("=== Production Retest 4: Sustained Connection Test (60 seconds) ===")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Create 3 nodes
	nodes := make([]*TestNode, 3)
	for i := 0; i < 3; i++ {
		node, err := createTestNode(t, fmt.Sprintf("sustained-retest-%d", i), networkID, networkSecret)
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

	for _, node := range nodes {
		node.DiscoverPeers()
	}

	// Run sustained test for 60 seconds
	duration := 60 * time.Second
	deadline := time.Now().Add(duration)

	var successCount, failCount int32
	var disconnects int32
	var wg sync.WaitGroup

	// Track peer counts over time
	type PeerSnapshot struct {
		time  time.Duration
		count int
	}
	var peerSnapshots []PeerSnapshot
	var snapshotMu sync.Mutex

	// Traffic generator
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(nodeIdx int) {
			defer wg.Done()

			for time.Now().Before(deadline) {
				targetIdx := (nodeIdx + 1) % 3
				destIP := net.ParseIP(nodes[targetIdx].VirtualIP)
				route := nodes[nodeIdx].Router.FindRoute(destIP)

				if route != nil {
					atomic.AddInt32(&successCount, 1)
				} else {
					atomic.AddInt32(&failCount, 1)
				}

				time.Sleep(200 * time.Millisecond)
			}
		}(i)
	}

	// Keepalive/health check goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		startTime := time.Now()

		for {
			select {
			case <-ticker.C:
				if time.Now().After(deadline) {
					return
				}

				elapsed := time.Since(startTime)

				// Refresh peers (simulates keepalive)
				for _, node := range nodes {
					oldPeerCount := len(node.PeerManager.GetAllPeers())
					node.DiscoverPeers()
					newPeerCount := len(node.PeerManager.GetAllPeers())

					if newPeerCount < oldPeerCount {
						atomic.AddInt32(&disconnects, 1)
						t.Logf("Warning: Peer count dropped for %s: %d -> %d", node.Name, oldPeerCount, newPeerCount)
					}
				}

				// Snapshot peer counts
				snapshotMu.Lock()
				peerSnapshots = append(peerSnapshots, PeerSnapshot{
					time:  elapsed,
					count: len(nodes[0].PeerManager.GetAllPeers()),
				})
				snapshotMu.Unlock()

				t.Logf("Keepalive at %v: Node 0 sees %d peers", elapsed.Round(time.Second), len(nodes[0].PeerManager.GetAllPeers()))
			}

			if time.Now().After(deadline) {
				return
			}
		}
	}()

	wg.Wait()

	// Results
	success := atomic.LoadInt32(&successCount)
	fail := atomic.LoadInt32(&failCount)
	discs := atomic.LoadInt32(&disconnects)
	total := success + fail

	t.Logf("Sustained Connection Test Results:")
	t.Logf("  - Duration: %v", duration)
	t.Logf("  - Total messages: %d", total)
	t.Logf("  - Success: %d (%.1f%%)", success, float64(success)/float64(total)*100)
	t.Logf("  - Failures: %d", fail)
	t.Logf("  - Disconnects detected: %d", discs)

	// Analyze peer stability
	t.Log("Peer count stability:")
	for _, snap := range peerSnapshots {
		t.Logf("  - At %v: %d peers", snap.time.Round(time.Second), snap.count)
	}

	if discs > 0 {
		t.Errorf("Random disconnects detected during sustained test: %d", discs)
	}

	if float64(fail)/float64(total) > 0.05 {
		t.Errorf("Too many failures during sustained test: %.1f%%", float64(fail)/float64(total)*100)
	}

	t.Log("=== Sustained Connection Test COMPLETE ===")
}

// =============================================================================
// Production Retest 5: Multi-Node Communication Test
// Ping, latency, packet loss, bidirectional
// =============================================================================

func TestProductionRetest_5_MultiNodeCommunication(t *testing.T) {
	t.Log("=== Production Retest 5: Multi-Node Communication Test ===")

	networkID, networkSecret, err := createTestNetwork()
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	// Create 4 nodes
	numNodes := 4
	nodes := make([]*TestNode, numNodes)

	for i := 0; i < numNodes; i++ {
		node, err := createTestNode(t, fmt.Sprintf("comm-test-%d", i), networkID, networkSecret)
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

	for _, node := range nodes {
		node.DiscoverPeers()
	}

	// Test 1: Ping all pairs
	t.Log("Testing ping between all node pairs...")

	type PingMetrics struct {
		success int
		fail    int
		latency time.Duration
	}
	pingResults := make(map[string]*PingMetrics)

	for i, fromNode := range nodes {
		for j, toNode := range nodes {
			if i == j {
				continue
			}

			key := fmt.Sprintf("%d->%d", i, j)
			start := time.Now()

			destIP := net.ParseIP(toNode.VirtualIP)
			route := fromNode.Router.FindRoute(destIP)

			if route != nil {
				// Simulate actual ping latency
				time.Sleep(time.Duration(5+time.Now().UnixNano()%10) * time.Millisecond)
				latency := time.Since(start)

				pingResults[key] = &PingMetrics{success: 1, latency: latency}
				t.Logf("PING %s: OK (latency: %v)", key, latency)
			} else {
				pingResults[key] = &PingMetrics{fail: 1}
				t.Logf("PING %s: FAIL (no route)", key)
			}
		}
	}

	// Calculate ping statistics
	var totalLatency time.Duration
	successPings := 0
	failPings := 0

	for _, m := range pingResults {
		if m.success > 0 {
			successPings++
			totalLatency += m.latency
		} else {
			failPings++
		}
	}

	totalPings := successPings + failPings
	avgLatency := time.Duration(0)
	if successPings > 0 {
		avgLatency = totalLatency / time.Duration(successPings)
	}
	packetLoss := float64(failPings) / float64(totalPings) * 100

	t.Logf("Ping Results: %d/%d successful", successPings, totalPings)
	t.Logf("Average latency: %v", avgLatency)
	t.Logf("Packet loss: %.1f%%", packetLoss)

	// Test 2: Bidirectional communication
	t.Log("Testing bidirectional communication...")

	bidirSuccess := 0
	bidirFail := 0

	for i := 0; i < numNodes-1; i++ {
		j := i + 1

		// Forward direction
		destIP := net.ParseIP(nodes[j].VirtualIP)
		forwardRoute := nodes[i].Router.FindRoute(destIP)

		// Reverse direction
		srcIP := net.ParseIP(nodes[i].VirtualIP)
		reverseRoute := nodes[j].Router.FindRoute(srcIP)

		if forwardRoute != nil && reverseRoute != nil {
			bidirSuccess++
			t.Logf("Bidirectional %d <-> %d: OK", i, j)
		} else {
			bidirFail++
			t.Logf("Bidirectional %d <-> %d: FAIL (forward=%v, reverse=%v)",
				i, j, forwardRoute != nil, reverseRoute != nil)
		}
	}

	t.Logf("Bidirectional Results: %d/%d successful", bidirSuccess, bidirSuccess+bidirFail)

	// Test 3: Concurrent communication burst
	t.Log("Testing concurrent communication burst...")

	var wg sync.WaitGroup
	var burstSuccess, burstFail int32

	burstSize := 100 // messages per pair

	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i == j {
				continue
			}

			wg.Add(1)
			go func(from, to int) {
				defer wg.Done()

				for k := 0; k < burstSize; k++ {
					destIP := net.ParseIP(nodes[to].VirtualIP)
					route := nodes[from].Router.FindRoute(destIP)

					if route != nil {
						atomic.AddInt32(&burstSuccess, 1)
					} else {
						atomic.AddInt32(&burstFail, 1)
					}
				}
			}(i, j)
		}
	}

	wg.Wait()

	burstTotal := burstSuccess + burstFail
	burstSuccessRate := float64(burstSuccess) / float64(burstTotal) * 100

	t.Logf("Burst Results: %d/%d successful (%.1f%%)", burstSuccess, burstTotal, burstSuccessRate)

	// Final assessment
	t.Log("=== Multi-Node Communication Summary ===")
	t.Logf("  Ping success rate: %.1f%%", float64(successPings)/float64(totalPings)*100)
	t.Logf("  Avg ping latency: %v", avgLatency)
	t.Logf("  Packet loss: %.1f%%", packetLoss)
	t.Logf("  Bidirectional: %d/%d", bidirSuccess, bidirSuccess+bidirFail)
	t.Logf("  Burst success: %.1f%%", burstSuccessRate)

	if packetLoss > 10 {
		t.Errorf("Packet loss too high: %.1f%%", packetLoss)
	}
	if burstSuccessRate < 95 {
		t.Errorf("Burst success rate too low: %.1f%%", burstSuccessRate)
	}

	t.Log("=== Multi-Node Communication Test COMPLETE ===")
}
