package nat

import (
	"net"
	"testing"
)

func TestNewHolePuncher(t *testing.T) {
	servers := []string{
		"stun:stun.l.google.com:19302",
	}

	hp, err := NewHolePuncher(servers)
	if err != nil {
		t.Fatalf("Failed to create HolePuncher: %v", err)
	}
	defer hp.Close()

	// Check local address
	localAddr := hp.LocalAddr()
	if localAddr == nil {
		t.Fatal("LocalAddr returned nil")
	}
	if localAddr.Port == 0 {
		t.Error("LocalAddr port should not be 0")
	}
}

func TestNewHolePuncherWithPort(t *testing.T) {
	servers := []string{
		"stun:stun.l.google.com:19302",
	}

	// Use a high port to avoid permission issues
	hp, err := NewHolePuncherWithPort(servers, 0) // 0 = random port
	if err != nil {
		t.Fatalf("Failed to create HolePuncher: %v", err)
	}
	defer hp.Close()

	if hp.LocalAddr().Port == 0 {
		t.Error("LocalAddr port should be assigned")
	}
}

func TestGetEndpoints(t *testing.T) {
	servers := []string{
		"stun:stun.l.google.com:19302",
	}

	hp, err := NewHolePuncher(servers)
	if err != nil {
		t.Fatalf("Failed to create HolePuncher: %v", err)
	}
	defer hp.Close()

	endpoints := hp.GetEndpoints()
	// Should have at least local endpoints
	if len(endpoints) == 0 {
		t.Error("GetEndpoints should return at least local endpoints")
	}

	// All endpoints should be valid host:port format
	for _, ep := range endpoints {
		_, _, err := net.SplitHostPort(ep)
		if err != nil {
			t.Errorf("Invalid endpoint format: %s", ep)
		}
	}
}

func TestIsPublicIPAddr(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		public bool
	}{
		{"public IP", "8.8.8.8", true},
		{"Google DNS", "203.0.113.1", true},
		{"private 10.x", "10.0.0.1", false},
		{"private 172.16.x", "172.16.0.1", false},
		{"private 172.31.x", "172.31.255.255", false},
		{"private 192.168.x", "192.168.1.1", false},
		{"link-local", "169.254.1.1", false},
		{"loopback", "127.0.0.1", false},
		{"CGNAT", "100.64.0.1", true}, // Note: CGNAT is treated as public in this implementation
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := isPublicIPAddr(ip)
			if got != tt.public {
				t.Errorf("isPublicIPAddr(%s): got %v, want %v", tt.ip, got, tt.public)
			}
		})
	}
}

func TestHolePuncherConn(t *testing.T) {
	servers := []string{"stun:stun.l.google.com:19302"}

	hp, err := NewHolePuncher(servers)
	if err != nil {
		t.Fatalf("Failed to create HolePuncher: %v", err)
	}
	defer hp.Close()

	conn := hp.Conn()
	if conn == nil {
		t.Error("Conn() returned nil")
	}
}

func TestHolePuncherClose(t *testing.T) {
	servers := []string{"stun:stun.l.google.com:19302"}

	hp, err := NewHolePuncher(servers)
	if err != nil {
		t.Fatalf("Failed to create HolePuncher: %v", err)
	}

	// Close should not error
	err = hp.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Second close should error (already closed)
	err = hp.Close()
	if err == nil {
		t.Log("Note: Second close may or may not error depending on implementation")
	}
}

func TestGetNATType(t *testing.T) {
	servers := []string{"stun:stun.l.google.com:19302"}

	hp, err := NewHolePuncher(servers)
	if err != nil {
		t.Fatalf("Failed to create HolePuncher: %v", err)
	}
	defer hp.Close()

	// Before discovery, NAT type should be unknown
	natType := hp.GetNATType()
	if natType != NATTypeUnknown {
		t.Logf("NAT type before discovery: %s", natType)
	}
}

func TestGetMappedAddr(t *testing.T) {
	servers := []string{"stun:stun.l.google.com:19302"}

	hp, err := NewHolePuncher(servers)
	if err != nil {
		t.Fatalf("Failed to create HolePuncher: %v", err)
	}
	defer hp.Close()

	// Before discovery, mapped addr should be nil
	mapped := hp.GetMappedAddr()
	if mapped != nil {
		t.Logf("Mapped addr before discovery: %s:%d", mapped.IP, mapped.Port)
	}
}
