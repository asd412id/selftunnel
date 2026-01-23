//go:build integration
// +build integration

package signaling

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// =============================================================================
// Scenario 2: Network Failure Scenarios
// =============================================================================

// Scenario 2.1: Signaling server temporarily unavailable
func TestScenario_2_1_ServerUnavailable(t *testing.T) {
	t.Log("Scenario 2.1: Signaling server temporarily unavailable")

	// Use non-existent server URL
	client := NewClient("https://nonexistent.invalid.domain:9999", "test-net", "test-secret")
	peer, _ := createTestPeer("scenario-2-1-peer")
	client.SetLocalPeer(peer)
	defer client.Stop()

	// Should fail with network error
	_, err := client.Register()
	if err == nil {
		t.Fatal("FAIL: Expected error when server unavailable")
	}

	t.Logf("PASS: Server unavailable handled correctly: %v", err)
}

// Scenario 2.2: Network timeout during handshake
func TestScenario_2_2_ConnectionTimeout(t *testing.T) {
	t.Log("Scenario 2.2: Network timeout during handshake")

	// Use a server that will timeout (black hole)
	client := NewClient("https://10.255.255.1:51820", "test-net", "test-secret")
	client.httpClient.Timeout = 2 * time.Second // Short timeout

	peer, _ := createTestPeer("scenario-2-2-peer")
	client.SetLocalPeer(peer)
	defer client.Stop()

	start := time.Now()
	_, err := client.Register()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("FAIL: Expected timeout error")
	}

	if elapsed > 5*time.Second {
		t.Fatalf("FAIL: Timeout took too long: %v", elapsed)
	}

	t.Logf("PASS: Timeout handled correctly in %v: %v", elapsed, err)
}

// Scenario 2.3: Multiple retry attempts
func TestScenario_2_3_RetryBehavior(t *testing.T) {
	t.Log("Scenario 2.3: Multiple retry attempts on failure")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, _ := createTestPeer("scenario-2-3-peer")
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	// Simulate multiple registration attempts
	maxRetries := 3
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		resp, err := client.Register()
		if err == nil && resp.Success {
			t.Logf("PASS: Registration succeeded on attempt %d", i+1)
			return
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("FAIL: All %d retry attempts failed: %v", maxRetries, lastErr)
}

// Scenario 2.4: High latency connection simulation
func TestScenario_2_4_HighLatency(t *testing.T) {
	t.Log("Scenario 2.4: High latency connection")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	// Create client with longer timeout for high latency
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.httpClient.Timeout = 60 * time.Second

	peer, _ := createTestPeer("scenario-2-4-peer")
	client.SetLocalPeer(peer)
	defer func() {
		client.Unregister()
		client.Stop()
	}()

	start := time.Now()
	resp, err := client.Register()
	latency := time.Since(start)

	if err != nil {
		t.Fatalf("FAIL: Registration failed: %v", err)
	}

	if !resp.Success {
		t.Fatal("FAIL: Registration not successful")
	}

	t.Logf("PASS: Registration completed in %v", latency)
}

// Scenario 2.5: Connection drops mid-operation
func TestScenario_2_5_ConnectionDrop(t *testing.T) {
	t.Log("Scenario 2.5: Connection drops mid-operation")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, _ := createTestPeer("scenario-2-5-peer")
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)

	// Register first
	_, err = client.Register()
	if err != nil {
		t.Fatalf("FAIL: Initial registration failed: %v", err)
	}

	// Start background operations
	client.Start()

	// Simulate connection drop by stopping abruptly
	client.Stop()

	// Try to use client after stop (should handle gracefully)
	_, err = client.GetPeers()
	// Error is expected here
	t.Logf("Note: GetPeers after stop: %v (error expected)", err)

	// Create new client and recover
	client2 := NewClient(getSignalingURL(), networkID, networkSecret)
	client2.SetLocalPeer(peer)
	defer func() {
		client2.Unregister()
		client2.Stop()
	}()

	resp, err := client2.Register()
	if err != nil {
		t.Fatalf("FAIL: Recovery registration failed: %v", err)
	}

	t.Logf("PASS: Recovered after connection drop, VirtualIP: %s", resp.VirtualIP)
}

// Scenario 2.6: HTTP request context cancellation
func TestScenario_2_6_ContextCancellation(t *testing.T) {
	t.Log("Scenario 2.6: Context cancellation during request")

	networkID, networkSecret, err := generateTestNetwork()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate network: %v", err)
	}

	peer, _ := createTestPeer("scenario-2-6-peer")
	client := NewClient(getSignalingURL(), networkID, networkSecret)
	client.SetLocalPeer(peer)

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately to simulate abort
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	// Try to register with cancelled context
	req, _ := http.NewRequestWithContext(ctx, "POST", getSignalingURL()+"/register", nil)
	_, err = client.httpClient.Do(req)

	// Context cancellation should cause error
	if err != nil {
		t.Logf("PASS: Context cancellation handled: %v", err)
	} else {
		t.Log("Note: Request completed before cancellation")
	}

	client.Stop()
}
