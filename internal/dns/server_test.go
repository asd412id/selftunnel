package dns

import (
	"net"
	"testing"
	"time"
)

// mockResolver implements PeerResolver for testing
type mockResolver struct {
	peers     map[string]string
	localName string
	localIP   string
}

func (m *mockResolver) GetPeerByName(name string) (virtualIP string, found bool) {
	ip, ok := m.peers[name]
	return ip, ok
}

func (m *mockResolver) GetLocalPeer() (name string, virtualIP string) {
	return m.localName, m.localIP
}

func TestDNSServer(t *testing.T) {
	resolver := &mockResolver{
		peers: map[string]string{
			"server-a":  "10.99.0.1",
			"server-b":  "10.99.0.2",
			"my-laptop": "10.99.0.3",
		},
		localName: "test-node",
		localIP:   "10.99.0.100",
	}

	cfg := Config{
		Port:   15353, // Use high port for testing
		Suffix: "selftunnel",
	}

	server := NewServer(resolver, cfg)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start DNS server: %v", err)
	}
	defer server.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test DNS query
	tests := []struct {
		name     string
		query    string
		expected string
		wantErr  bool
	}{
		{"resolve server-a", "server-a.selftunnel", "10.99.0.1", false},
		{"resolve server-b", "server-b.selftunnel", "10.99.0.2", false},
		{"resolve local", "test-node.selftunnel", "10.99.0.100", false},
		{"case insensitive", "Server-A.selftunnel", "10.99.0.1", false},
		{"unknown peer", "unknown.selftunnel", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := resolveDNS(tt.query, 15353)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for %s, got IP %s", tt.query, ip)
				}
				return
			}
			if err != nil {
				t.Errorf("Failed to resolve %s: %v", tt.query, err)
				return
			}
			if ip != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, ip)
			}
		})
	}
}

// resolveDNS sends a DNS query and returns the resolved IP
func resolveDNS(name string, port int) (string, error) {
	// Build DNS query
	query := buildDNSQueryPacket(name)

	// Send query
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", string(rune(port))))
	if err != nil {
		// Use sprintf for port
		addr := "127.0.0.1:" + itoa(port)
		conn, err = net.Dial("udp", addr)
		if err != nil {
			return "", err
		}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write(query); err != nil {
		return "", err
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return "", err
	}

	return parseDNSResponseIP(response[:n])
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	idx := len(b)
	for i > 0 {
		idx--
		b[idx] = byte('0' + i%10)
		i /= 10
	}
	return string(b[idx:])
}

func buildDNSQueryPacket(name string) []byte {
	buf := make([]byte, 0, 512)

	// Header
	buf = append(buf, 0x00, 0x01) // ID
	buf = append(buf, 0x01, 0x00) // Flags: RD=1
	buf = append(buf, 0x00, 0x01) // QDCOUNT=1
	buf = append(buf, 0x00, 0x00) // ANCOUNT=0
	buf = append(buf, 0x00, 0x00) // NSCOUNT=0
	buf = append(buf, 0x00, 0x00) // ARCOUNT=0

	// Question
	buf = appendDNSName(buf, name)
	buf = append(buf, 0x00, 0x01) // QTYPE=A
	buf = append(buf, 0x00, 0x01) // QCLASS=IN

	return buf
}

func parseDNSResponseIP(data []byte) (string, error) {
	if len(data) < 12 {
		return "", net.InvalidAddrError("response too short")
	}

	// Check RCODE
	rcode := data[3] & 0x0F
	if rcode != 0 {
		return "", net.InvalidAddrError("NXDOMAIN or error")
	}

	// Check ANCOUNT
	ancount := int(data[6])<<8 | int(data[7])
	if ancount == 0 {
		return "", net.InvalidAddrError("no answers")
	}

	// Skip header (12 bytes) and question section
	offset := 12
	for offset < len(data) {
		if data[offset] == 0 {
			offset++
			break
		}
		offset += int(data[offset]) + 1
	}
	offset += 4 // Skip QTYPE and QCLASS

	// Parse first answer
	if offset >= len(data) {
		return "", net.InvalidAddrError("malformed response")
	}

	// Skip name (could be pointer or labels)
	if data[offset]&0xC0 == 0xC0 {
		offset += 2 // Pointer
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}

	if offset+10 > len(data) {
		return "", net.InvalidAddrError("answer too short")
	}

	// Skip TYPE, CLASS, TTL (10 bytes total before RDLENGTH)
	offset += 8

	rdlength := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if rdlength != 4 || offset+4 > len(data) {
		return "", net.InvalidAddrError("invalid A record")
	}

	ip := net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
	return ip.String(), nil
}
