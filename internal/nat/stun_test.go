package nat

import (
	"net"
	"testing"
)

func TestNewSTUNClient(t *testing.T) {
	servers := []string{
		"stun:stun.l.google.com:19302",
		"stun:stun1.l.google.com:19302",
	}

	client := NewSTUNClient(servers)
	if client == nil {
		t.Fatal("NewSTUNClient returned nil")
	}
}

func TestParseSTUNURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{
			name:     "with scheme and port",
			input:    "stun:stun.l.google.com:19302",
			wantHost: "stun.l.google.com",
			wantPort: 19302,
			wantErr:  false,
		},
		{
			name:     "with scheme no port",
			input:    "stun:stun.cloudflare.com",
			wantHost: "stun.cloudflare.com",
			wantPort: 3478, // default STUN port
			wantErr:  false,
		},
		{
			name:     "host:port only",
			input:    "stun.example.com:3478",
			wantHost: "stun.example.com",
			wantPort: 3478,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseSTUNURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if host != tt.wantHost {
				t.Errorf("Host: got %s, want %s", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("Port: got %d, want %d", port, tt.wantPort)
			}
		})
	}
}

func TestNATTypeString(t *testing.T) {
	tests := []struct {
		natType NATType
		want    string
	}{
		{NATTypeUnknown, "Unknown"},
		{NATTypeNone, "None (Public IP)"},
		{NATTypeFullCone, "Full Cone"},
		{NATTypeRestrictedCone, "Restricted Cone"},
		{NATTypePortRestricted, "Port Restricted Cone"},
		{NATTypeSymmetric, "Symmetric"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.natType.String()
			if got != tt.want {
				t.Errorf("String(): got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestMappedAddress(t *testing.T) {
	ma := &MappedAddress{
		IP:   net.ParseIP("203.0.113.1"),
		Port: 12345,
	}

	// Test IP and Port fields
	if ma.IP.String() != "203.0.113.1" {
		t.Errorf("IP: got %s, want 203.0.113.1", ma.IP.String())
	}
	if ma.Port != 12345 {
		t.Errorf("Port: got %d, want 12345", ma.Port)
	}
}

// parseSTUNURL is a helper function duplicated for testing
func parseSTUNURL(url string) (host string, port int, err error) {
	// Remove stun: or stuns: prefix
	s := url
	if len(s) > 5 && s[:5] == "stun:" {
		s = s[5:]
	} else if len(s) > 6 && s[:6] == "stuns:" {
		s = s[6:]
	}

	// Parse host:port
	host, portStr, splitErr := net.SplitHostPort(s)
	if splitErr != nil {
		// No port specified, use default
		host = s
		port = 3478
		return host, port, nil
	}

	// Parse port
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return "", 0, &net.AddrError{Err: "invalid port", Addr: portStr}
		}
		port = port*10 + int(c-'0')
	}

	return host, port, nil
}
