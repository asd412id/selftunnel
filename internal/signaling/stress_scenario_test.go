//go:build integration
// +build integration

package signaling

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// Scenario 5: Stress & Load Scenarios
// =============================================================================

// Scenario 5.1: Rapid connect/disconnect cycles
func TestScenario_5_1_RapidConnectDisconnect(t *testing.T) {
	t.Log("Scenario 5.1: Rapid connect/disconnect cycles")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	cycles := 5
	successCount := 0

	for i := 0; i < cycles; i++ {
		peer, _ := createTestPeer("scenario-5-1-rapid")
		client := NewClient(getSignalingURL(), networkID, networkSecret)
		client.SetLocalPeer(peer)

		// Connect
		resp, err := client.Register()
		if err != nil {
			t.Logf("Cycle %d: Connect failed: %v", i+1, err)
			client.Stop()
			continue
		}

		if resp.Success {
			successCount++
		}

		// Disconnect immediately
		client.Unregister()
		client.Stop()

		// Small delay between cycles
		time.Sleep(100 * time.Millisecond)
	}

	if successCount < cycles/2 {
		t.Fatalf("FAIL: Only %d/%d rapid cycles succeeded", successCount, cycles)
	}

	t.Logf("PASS: %d/%d rapid connect/disconnect cycles succeeded", successCount, cycles)
}

// Scenario 5.2: Many peers connecting simultaneously (thundering herd)
func TestScenario_5_2_ThunderingHerd(t *testing.T) {
	t.Log("Scenario 5.2: Thundering herd - many peers connecting simultaneously")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	numPeers := 20
	var successCount int32
	var wg sync.WaitGroup

	// Create all clients
	clients := make([]*Client, numPeers)
	for i := 0; i < numPeers; i++ {
		peer, _ := createTestPeer("scenario-5-2-herd-" + string(rune('a'+i%26)) + string(rune('0'+i/26)))
		client := NewClient(getSignalingURL(), networkID, networkSecret)
		client.SetLocalPeer(peer)
		clients[i] = client
	}

	// Start all connections simultaneously
	startSignal := make(chan struct{})

	for i := 0; i < numPeers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			<-startSignal // Wait for start signal

			resp, err := clients[idx].Register()
			if err == nil && resp.Success {
				atomic.AddInt32(&successCount, 1)
			}
		}(i)
	}

	// Fire! All connect at once
	close(startSignal)

	// Wait for all with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All completed
	case <-time.After(30 * time.Second):
		t.Fatal("FAIL: Thundering herd test timed out")
	}

	// Cleanup
	for _, client := range clients {
		client.Unregister()
		client.Stop()
	}

	success := int(atomic.LoadInt32(&successCount))
	if success < numPeers/2 {
		t.Fatalf("FAIL: Only %d/%d peers connected in thundering herd", success, numPeers)
	}

	t.Logf("PASS: Thundering herd handled - %d/%d peers connected", success, numPeers)
}

// Scenario 5.3: Sustained connection load
func TestScenario_5_3_SustainedLoad(t *testing.T) {
	t.Log("Scenario 5.3: Sustained connection load")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, _ := createTestPeer("scenario-5-3-sustained")
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	// Register
	_, err = client.Register()
	if err != nil {
		t.Fatalf("FAIL: Initial registration failed: %v", err)
	}

	// Sustained operations
	duration := 5 * time.Second
	interval := 500 * time.Millisecond
	operationCount := 0
	errorCount := 0

	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		// Heartbeat
		err := client.Heartbeat()
		if err != nil {
			errorCount++
		}
		operationCount++

		// Get peers
		_, err = client.GetPeers()
		if err != nil {
			errorCount++
		}
		operationCount++

		time.Sleep(interval)
	}

	errorRate := float64(errorCount) / float64(operationCount) * 100
	if errorRate > 10 {
		t.Fatalf("FAIL: Error rate too high: %.1f%% (%d/%d)", errorRate, errorCount, operationCount)
	}

	t.Logf("PASS: Sustained load completed - %d operations, %.1f%% error rate", operationCount, errorRate)
}

// Scenario 5.4: Long-running connection stability
func TestScenario_5_4_LongRunning(t *testing.T) {
	t.Log("Scenario 5.4: Long-running connection stability (10 seconds)")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, _ := createTestPeer("scenario-5-4-longrun")
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	// Register and start
	_, err = client.Register()
	if err != nil {
		t.Fatalf("FAIL: Registration failed: %v", err)
	}

	client.Start()

	// Run for specified duration
	testDuration := 10 * time.Second
	checkInterval := 2 * time.Second
	checks := 0
	failures := 0

	deadline := time.Now().Add(testDuration)
	for time.Now().Before(deadline) {
		time.Sleep(checkInterval)

		// Verify connection still works
		peers, err := client.GetPeers()
		if err != nil {
			failures++
			t.Logf("Check %d: FAIL - %v", checks+1, err)
		} else {
			t.Logf("Check %d: OK - %d peers", checks+1, len(peers))
		}
		checks++
	}

	if failures > checks/3 {
		t.Fatalf("FAIL: Too many failures during long-running test: %d/%d", failures, checks)
	}

	t.Logf("PASS: Long-running connection stable - %d/%d checks passed", checks-failures, checks)
}

// Scenario 5.5: Burst traffic pattern
func TestScenario_5_5_BurstTraffic(t *testing.T) {
	t.Log("Scenario 5.5: Burst traffic pattern")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, _ := createTestPeer("scenario-5-5-burst")
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	_, err = client.Register()
	if err != nil {
		t.Fatalf("FAIL: Registration failed: %v", err)
	}

	// Burst pattern: rapid requests followed by idle
	bursts := 3
	requestsPerBurst := 10
	totalSuccess := 0

	for burst := 0; burst < bursts; burst++ {
		t.Logf("Burst %d starting...", burst+1)

		burstSuccess := 0
		for i := 0; i < requestsPerBurst; i++ {
			_, err := client.GetPeers()
			if err == nil {
				burstSuccess++
			}
		}
		totalSuccess += burstSuccess

		t.Logf("Burst %d: %d/%d requests succeeded", burst+1, burstSuccess, requestsPerBurst)

		// Idle period between bursts
		time.Sleep(1 * time.Second)
	}

	totalRequests := bursts * requestsPerBurst
	successRate := float64(totalSuccess) / float64(totalRequests) * 100

	if successRate < 80 {
		t.Fatalf("FAIL: Burst success rate too low: %.1f%%", successRate)
	}

	t.Logf("PASS: Burst traffic handled - %.1f%% success rate", successRate)
}
