package dns

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	DefaultDNSPort   = 53
	DefaultDNSSuffix = "selftunnel"
)

// PeerResolver interface for looking up peer IPs by name
type PeerResolver interface {
	GetPeerByName(name string) (virtualIP string, found bool)
	GetLocalPeer() (name string, virtualIP string)
}

// Server is a simple DNS server for resolving peer names
type Server struct {
	resolver PeerResolver
	port     int
	suffix   string
	upstream string
	bindIP   string
	conn     *net.UDPConn
	mu       sync.RWMutex
	running  bool
	stopCh   chan struct{}
}

// Config holds DNS server configuration
type Config struct {
	Port     int    // UDP port to listen on (default 53)
	Suffix   string // Domain suffix (default "selftunnel")
	Upstream string // Upstream DNS server for non-local queries (default "8.8.8.8:53")
	BindIP   string // IP to bind to (default "", meaning all interfaces)
}

// NewServer creates a new DNS server
func NewServer(resolver PeerResolver, cfg Config) *Server {
	if cfg.Port == 0 {
		cfg.Port = DefaultDNSPort
	}
	if cfg.Suffix == "" {
		cfg.Suffix = DefaultDNSSuffix
	}
	if cfg.Upstream == "" {
		cfg.Upstream = "8.8.8.8:53"
	}

	return &Server{
		resolver: resolver,
		port:     cfg.Port,
		suffix:   cfg.Suffix,
		upstream: cfg.Upstream,
		bindIP:   cfg.BindIP,
		stopCh:   make(chan struct{}),
	}
}

// Start starts the DNS server
func (s *Server) Start() error {
	var addr *net.UDPAddr
	if s.bindIP != "" {
		ip := net.ParseIP(s.bindIP)
		if ip == nil {
			return fmt.Errorf("invalid bind IP: %s", s.bindIP)
		}
		addr = &net.UDPAddr{IP: ip, Port: s.port}
	} else {
		addr = &net.UDPAddr{Port: s.port}
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s:%d: %w", s.bindIP, s.port, err)
	}
	s.conn = conn

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	go s.serve()

	bindAddr := "0.0.0.0"
	if s.bindIP != "" {
		bindAddr = s.bindIP
	}
	log.Printf("DNS server started on %s:%d (suffix: .%s)", bindAddr, s.port, s.suffix)
	return nil
}

// Stop stops the DNS server
func (s *Server) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()

	close(s.stopCh)
	if s.conn != nil {
		s.conn.Close()
	}
	log.Println("DNS server stopped")
}

func (s *Server) serve() {
	buf := make([]byte, 512)
	log.Printf("[DNS] Server listening, waiting for queries...")
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.mu.RLock()
			running := s.running
			s.mu.RUnlock()
			if !running {
				return
			}
			log.Printf("[DNS] ReadFromUDP error: %v", err)
			continue
		}

		log.Printf("[DNS] Received %d bytes from %s", n, remoteAddr)
		go s.handleQuery(buf[:n], remoteAddr)
	}
}

func (s *Server) handleQuery(data []byte, remoteAddr *net.UDPAddr) {
	if len(data) < 12 {
		return
	}

	// Parse DNS query
	query, err := parseDNSQuery(data)
	if err != nil {
		log.Printf("[DNS] Failed to parse query from %s: %v", remoteAddr, err)
		return
	}

	log.Printf("[DNS] Received query from %s: %s (type=%d)", remoteAddr, query.Name, query.QType)

	// Check if it's a query for our suffix
	name := strings.ToLower(query.Name)
	suffix := "." + s.suffix + "."

	if strings.HasSuffix(name, suffix) {
		// Extract peer name
		peerName := strings.TrimSuffix(name, suffix)
		peerName = strings.TrimSuffix(peerName, ".") // Remove trailing dot if any

		log.Printf("[DNS] Looking up peer: '%s'", peerName)

		// Check if it's the local node
		localName, localIP := s.resolver.GetLocalPeer()
		if strings.EqualFold(peerName, localName) {
			log.Printf("[DNS] Query for local peer %s -> %s", peerName, localIP)
			response := buildDNSResponse(query, localIP)
			s.conn.WriteToUDP(response, remoteAddr)
			return
		}

		// Look up peer - try original name first
		if ip, found := s.resolver.GetPeerByName(peerName); found {
			log.Printf("[DNS] Query for peer %s -> %s", peerName, ip)
			response := buildDNSResponse(query, ip)
			s.conn.WriteToUDP(response, remoteAddr)
			return
		}

		// Try with underscores replaced by dashes (DNS doesn't like underscores)
		altName := strings.ReplaceAll(peerName, "-", "_")
		if altName != peerName {
			if ip, found := s.resolver.GetPeerByName(altName); found {
				log.Printf("[DNS] Query for peer %s (alt: %s) -> %s", peerName, altName, ip)
				response := buildDNSResponse(query, ip)
				s.conn.WriteToUDP(response, remoteAddr)
				return
			}
		}

		// Try with dashes replaced by underscores
		altName2 := strings.ReplaceAll(peerName, "_", "-")
		if altName2 != peerName {
			if ip, found := s.resolver.GetPeerByName(altName2); found {
				log.Printf("[DNS] Query for peer %s (alt: %s) -> %s", peerName, altName2, ip)
				response := buildDNSResponse(query, ip)
				s.conn.WriteToUDP(response, remoteAddr)
				return
			}
		}

		// Peer not found - return NXDOMAIN
		log.Printf("[DNS] Query for unknown peer %s -> NXDOMAIN", peerName)
		response := buildNXDomainResponse(query)
		s.conn.WriteToUDP(response, remoteAddr)
		return
	}

	// Forward to upstream DNS
	upstreamResponse, err := s.forwardToUpstream(data)
	if err != nil {
		// Return SERVFAIL
		response := buildServFailResponse(query)
		s.conn.WriteToUDP(response, remoteAddr)
		return
	}
	s.conn.WriteToUDP(upstreamResponse, remoteAddr)
}

func (s *Server) forwardToUpstream(query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", s.upstream)
	if err != nil {
		return nil, fmt.Errorf("failed to dial upstream DNS: %w", err)
	}
	defer conn.Close()

	// Set deadline to prevent blocking forever (bug fix: resource_leak.2)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("failed to write to upstream DNS: %w", err)
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read from upstream DNS: %w", err)
	}

	return response[:n], nil
}

// DNSQuery represents a parsed DNS query
type DNSQuery struct {
	ID     uint16
	Name   string
	QType  uint16
	QClass uint16
}

func parseDNSQuery(data []byte) (*DNSQuery, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("packet too short")
	}

	query := &DNSQuery{
		ID: binary.BigEndian.Uint16(data[0:2]),
	}

	// Parse question section
	offset := 12
	var nameParts []string
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if offset+1+length > len(data) {
			return nil, fmt.Errorf("malformed name")
		}
		nameParts = append(nameParts, string(data[offset+1:offset+1+length]))
		offset += 1 + length
	}
	query.Name = strings.Join(nameParts, ".") + "."

	if offset+4 > len(data) {
		return nil, fmt.Errorf("missing qtype/qclass")
	}
	query.QType = binary.BigEndian.Uint16(data[offset : offset+2])
	query.QClass = binary.BigEndian.Uint16(data[offset+2 : offset+4])

	return query, nil
}

func buildDNSResponse(query *DNSQuery, ip string) []byte {
	response := make([]byte, 0, 512)

	// Header
	response = append(response, byte(query.ID>>8), byte(query.ID)) // ID
	response = append(response, 0x81, 0x80)                        // Flags: QR=1, AA=1, RD=1, RA=1
	response = append(response, 0x00, 0x01)                        // QDCOUNT=1
	response = append(response, 0x00, 0x01)                        // ANCOUNT=1
	response = append(response, 0x00, 0x00)                        // NSCOUNT=0
	response = append(response, 0x00, 0x00)                        // ARCOUNT=0

	// Question section (copy from query)
	response = appendDNSName(response, query.Name)
	response = append(response, byte(query.QType>>8), byte(query.QType))
	response = append(response, byte(query.QClass>>8), byte(query.QClass))

	// Answer section
	response = appendDNSName(response, query.Name)
	response = append(response, 0x00, 0x01)             // TYPE=A
	response = append(response, 0x00, 0x01)             // CLASS=IN
	response = append(response, 0x00, 0x00, 0x00, 0x3c) // TTL=60
	response = append(response, 0x00, 0x04)             // RDLENGTH=4

	// Parse IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return buildNXDomainResponse(query)
	}
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return buildNXDomainResponse(query)
	}
	response = append(response, ipv4...)

	return response
}

func buildNXDomainResponse(query *DNSQuery) []byte {
	response := make([]byte, 0, 512)

	// Header with NXDOMAIN (RCODE=3)
	response = append(response, byte(query.ID>>8), byte(query.ID))
	response = append(response, 0x81, 0x83) // Flags: QR=1, AA=1, RD=1, RA=1, RCODE=3
	response = append(response, 0x00, 0x01) // QDCOUNT=1
	response = append(response, 0x00, 0x00) // ANCOUNT=0
	response = append(response, 0x00, 0x00) // NSCOUNT=0
	response = append(response, 0x00, 0x00) // ARCOUNT=0

	// Question section
	response = appendDNSName(response, query.Name)
	response = append(response, byte(query.QType>>8), byte(query.QType))
	response = append(response, byte(query.QClass>>8), byte(query.QClass))

	return response
}

func buildServFailResponse(query *DNSQuery) []byte {
	response := make([]byte, 0, 512)

	// Header with SERVFAIL (RCODE=2)
	response = append(response, byte(query.ID>>8), byte(query.ID))
	response = append(response, 0x81, 0x82) // Flags: QR=1, AA=1, RD=1, RA=1, RCODE=2
	response = append(response, 0x00, 0x01) // QDCOUNT=1
	response = append(response, 0x00, 0x00) // ANCOUNT=0
	response = append(response, 0x00, 0x00) // NSCOUNT=0
	response = append(response, 0x00, 0x00) // ARCOUNT=0

	// Question section
	response = appendDNSName(response, query.Name)
	response = append(response, byte(query.QType>>8), byte(query.QType))
	response = append(response, byte(query.QClass>>8), byte(query.QClass))

	return response
}

func appendDNSName(buf []byte, name string) []byte {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)
	return buf
}
