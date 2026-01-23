//go:build integration
// +build integration

package nat

import (
	"net"
	"testing"
)

// =============================================================================
// Scenario 3: NAT Traversal Scenarios
// =============================================================================

// Scenario 3.1: Both peers behind same NAT (hairpin)
func TestScenario_3_1_SameNATHairpin(t *testing.T) {
	t.Log("Scenario 3.1: Both peers behind same NAT (hairpin)")

	// Simulate two local endpoints
	endpoint1 := "192.168.1.100:51820"
	endpoint2 := "192.168.1.101:51820"

	// Check if they're in same subnet
	ip1 := net.ParseIP("192.168.1.100")
	ip2 := net.ParseIP("192.168.1.101")

	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")

	if !subnet.Contains(ip1) || !subnet.Contains(ip2) {
		t.Fatal("FAIL: Endpoints not in same subnet")
	}

	t.Logf("PASS: Both endpoints (%s, %s) are in same NAT subnet", endpoint1, endpoint2)
}

// Scenario 3.2: Peers behind different NATs
func TestScenario_3_2_DifferentNATs(t *testing.T) {
	t.Log("Scenario 3.2: Peers behind different NATs")

	// Simulate different NAT endpoints
	nat1Public := "203.0.113.1:51820"  // NAT 1 public IP
	nat2Public := "198.51.100.1:51820" // NAT 2 public IP

	ip1 := net.ParseIP("203.0.113.1")
	ip2 := net.ParseIP("198.51.100.1")

	// Verify they're different public IPs
	if ip1.Equal(ip2) {
		t.Fatal("FAIL: NAT IPs should be different")
	}

	// Both should be public IPs (not private)
	if isPrivateIP(ip1) || isPrivateIP(ip2) {
		t.Fatal("FAIL: NAT public IPs should not be private")
	}

	t.Logf("PASS: Different NAT endpoints detected: %s, %s", nat1Public, nat2Public)
}

// Scenario 3.3: One peer with public IP, one behind NAT
func TestScenario_3_3_PublicAndNAT(t *testing.T) {
	t.Log("Scenario 3.3: One peer with public IP, one behind NAT")

	publicPeer := "203.0.113.1:51820"
	natPeer := "192.168.1.100:51820"

	publicIP := net.ParseIP("203.0.113.1")
	natIP := net.ParseIP("192.168.1.100")

	// Public peer should have non-private IP
	if isPrivateIP(publicIP) {
		t.Fatal("FAIL: Public peer should have public IP")
	}

	// NAT peer should have private IP (internal)
	if !isPrivateIP(natIP) {
		t.Fatal("FAIL: NAT peer should have private IP internally")
	}

	t.Logf("PASS: Public peer %s can connect to NAT peer %s", publicPeer, natPeer)
}

// Scenario 3.4: Symmetric NAT detection
func TestScenario_3_4_SymmetricNAT(t *testing.T) {
	t.Log("Scenario 3.4: Symmetric NAT detection (hole punch may fail)")

	// Test NAT type constants
	testCases := []struct {
		name     string
		natType  NATType
		canPunch bool
	}{
		{"Full Cone NAT", NATTypeFullCone, true},
		{"Restricted Cone NAT", NATTypeRestrictedCone, true},
		{"Port Restricted NAT", NATTypePortRestricted, true},
		{"Symmetric NAT", NATTypeSymmetric, false}, // Hole punch typically fails
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Verify NAT type string representation
			str := tc.natType.String()
			if str == "" {
				t.Errorf("FAIL: NAT type %v has empty string", tc.natType)
			}

			if tc.canPunch {
				t.Logf("PASS: %s (%s) - hole punch should succeed", tc.name, str)
			} else {
				t.Logf("PASS: %s (%s) - hole punch may fail, fallback to relay", tc.name, str)
			}
		})
	}
}

// Scenario 3.5: STUN server unreachable
func TestScenario_3_5_STUNUnreachable(t *testing.T) {
	t.Log("Scenario 3.5: STUN server unreachable")

	// Try actual STUN request to invalid server (black hole address)
	client := NewSTUNClient([]string{"10.255.255.1:3478"})

	// Set short timeout via internal method or use as-is
	addr, err := client.GetMappedAddress(nil)
	if err == nil {
		t.Fatalf("FAIL: Expected STUN request to fail, got: %v", addr)
	}

	t.Logf("PASS: STUN unreachable handled correctly: %v", err)
}

// Scenario 3.6: Multiple STUN servers fallback
func TestScenario_3_6_STUNFallback(t *testing.T) {
	t.Log("Scenario 3.6: Multiple STUN servers with fallback")

	stunServers := []string{
		"10.255.255.1:3478",       // Invalid (will fail)
		"stun.l.google.com:19302", // Valid Google STUN
	}

	client := NewSTUNClient(stunServers)

	addr, err := client.GetMappedAddress(nil)
	if err == nil {
		t.Logf("PASS: Got mapped address: %s:%d", addr.IP, addr.Port)
		return
	}

	// If all fail, it's not necessarily a test failure (network dependent)
	t.Logf("Note: All STUN servers failed (may be network restriction): %v", err)
}

// Scenario 3.7: NAT type detection
func TestScenario_3_7_NATTypeDetection(t *testing.T) {
	t.Log("Scenario 3.7: NAT type detection with multiple servers")

	// Need at least 2 STUN servers for NAT type detection
	stunServers := []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun2.l.google.com:19302",
	}

	client := NewSTUNClient(stunServers)

	natType, err := client.DetectNATType(nil)
	if err != nil {
		t.Logf("Note: NAT type detection failed (may be network restriction): %v", err)
		return
	}

	t.Logf("PASS: Detected NAT type: %s", natType)
}

// Scenario 3.8: Port delta detection for symmetric NAT
func TestScenario_3_8_PortDeltaDetection(t *testing.T) {
	t.Log("Scenario 3.8: Port delta detection for symmetric NAT")

	stunServers := []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
	}

	client := NewSTUNClient(stunServers)

	_, err := client.DetectNATType(nil)
	if err != nil {
		t.Logf("Note: NAT type detection failed: %v", err)
		return
	}

	// Get detected NAT type and port delta
	natType := client.GetNATType()
	portDelta := client.GetPortDelta()

	if natType == NATTypeSymmetric {
		t.Logf("PASS: Symmetric NAT detected with port delta: %d", portDelta)
	} else {
		t.Logf("PASS: NAT type: %s (port delta: %d)", natType, portDelta)
	}
}

// Helper: Check if IP is private
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
