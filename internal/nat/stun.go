package nat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"time"
)

const (
	stunMagicCookie          = 0x2112A442
	stunBindingRequest       = 0x0001
	stunBindingResponse      = 0x0101
	stunAttrMappedAddress    = 0x0001
	stunAttrXorMappedAddress = 0x0020
	stunHeaderSize           = 20
)

// NATType represents the type of NAT
type NATType int

const (
	NATTypeUnknown NATType = iota
	NATTypeNone            // No NAT (public IP)
	NATTypeFullCone
	NATTypeRestrictedCone
	NATTypePortRestricted
	NATTypeSymmetric
)

func (n NATType) String() string {
	switch n {
	case NATTypeNone:
		return "None (Public IP)"
	case NATTypeFullCone:
		return "Full Cone"
	case NATTypeRestrictedCone:
		return "Restricted Cone"
	case NATTypePortRestricted:
		return "Port Restricted Cone"
	case NATTypeSymmetric:
		return "Symmetric"
	default:
		return "Unknown"
	}
}

type STUNClient struct {
	servers   []string
	timeout   time.Duration
	conn      *net.UDPConn // shared connection (optional)
	natType   NATType
	portDelta int // detected port increment for symmetric NAT
}

type MappedAddress struct {
	IP   net.IP
	Port int
}

func NewSTUNClient(servers []string) *STUNClient {
	return &STUNClient{
		servers: servers,
		timeout: 3 * time.Second,
	}
}

// SetConn sets a shared UDP connection for STUN queries
func (c *STUNClient) SetConn(conn *net.UDPConn) {
	c.conn = conn
}

// GetNATType returns the detected NAT type
func (c *STUNClient) GetNATType() NATType {
	return c.natType
}

// GetPortDelta returns the detected port increment for symmetric NAT
func (c *STUNClient) GetPortDelta() int {
	return c.portDelta
}

// DetectNATType queries multiple STUN servers to detect NAT type
func (c *STUNClient) DetectNATType(localAddr *net.UDPAddr) (NATType, error) {
	if len(c.servers) < 2 {
		return NATTypeUnknown, errors.New("need at least 2 STUN servers to detect NAT type")
	}

	// Query multiple STUN servers to see if we get same or different ports
	var mappings []*MappedAddress
	var ports []int

	for i := 0; i < min(len(c.servers), 3); i++ {
		addr, err := c.queryServer(c.servers[i], localAddr)
		if err != nil {
			continue
		}
		mappings = append(mappings, addr)
		ports = append(ports, addr.Port)
	}

	if len(mappings) < 2 {
		return NATTypeUnknown, errors.New("could not get enough STUN responses")
	}

	// Check if local IP is same as mapped IP (no NAT)
	if localAddr != nil && mappings[0].IP.Equal(localAddr.IP) {
		c.natType = NATTypeNone
		return NATTypeNone, nil
	}

	// Check if all ports are the same
	allSame := true
	for i := 1; i < len(ports); i++ {
		if ports[i] != ports[0] {
			allSame = false
			break
		}
	}

	if allSame {
		// Same port to different servers = Cone NAT (not symmetric)
		c.natType = NATTypePortRestricted // Assume port restricted (most common)
		log.Printf("[STUN] NAT Type: Cone NAT (port %d same across servers)", ports[0])
		return NATTypePortRestricted, nil
	}

	// Different ports = Symmetric NAT
	c.natType = NATTypeSymmetric

	// Try to detect port increment pattern
	sort.Ints(ports)
	deltas := make([]int, len(ports)-1)
	for i := 1; i < len(ports); i++ {
		deltas[i-1] = ports[i] - ports[i-1]
	}

	// Check if deltas are consistent
	if len(deltas) >= 2 {
		avgDelta := 0
		for _, d := range deltas {
			avgDelta += d
		}
		avgDelta /= len(deltas)
		c.portDelta = avgDelta
		log.Printf("[STUN] NAT Type: Symmetric (ports: %v, avg delta: %d)", ports, avgDelta)
	} else if len(deltas) == 1 {
		c.portDelta = deltas[0]
		log.Printf("[STUN] NAT Type: Symmetric (ports: %v, delta: %d)", ports, c.portDelta)
	}

	return NATTypeSymmetric, nil
}

// GetMappedAddress queries STUN servers to get the public IP and port
func (c *STUNClient) GetMappedAddress(localAddr *net.UDPAddr) (*MappedAddress, error) {
	if len(c.servers) == 0 {
		return nil, errors.New("no STUN servers configured")
	}

	// If using shared connection, query sequentially to avoid read conflicts
	if c.conn != nil {
		var lastErr error
		for _, server := range c.servers {
			addr, err := c.queryServer(server, localAddr)
			if err == nil {
				return addr, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, fmt.Errorf("all STUN servers failed: %w", lastErr)
		}
		return nil, errors.New("no STUN servers configured")
	}

	// Query servers in parallel when using separate connections
	type result struct {
		addr *MappedAddress
		err  error
	}

	results := make(chan result, len(c.servers))

	for _, server := range c.servers {
		go func(srv string) {
			addr, err := c.queryServer(srv, localAddr)
			results <- result{addr, err}
		}(server)
	}

	// Wait for first successful result or all failures
	var lastErr error
	for i := 0; i < len(c.servers); i++ {
		res := <-results
		if res.err == nil {
			return res.addr, nil
		}
		lastErr = res.err
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all STUN servers failed: %w", lastErr)
	}
	return nil, errors.New("no STUN servers configured")
}

func (c *STUNClient) queryServer(server string, localAddr *net.UDPAddr) (*MappedAddress, error) {
	// Parse STUN URI
	stunAddr, err := parseSTUNURI(server)
	if err != nil {
		return nil, err
	}

	// Resolve server address
	serverAddr, err := net.ResolveUDPAddr("udp", stunAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN server: %w", err)
	}

	// Build STUN binding request
	request := buildBindingRequest()

	// Use shared connection if available
	if c.conn != nil {
		// Use WriteToUDP/ReadFromUDP for shared connection
		c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
		if _, err := c.conn.WriteToUDP(request, serverAddr); err != nil {
			return nil, fmt.Errorf("failed to send STUN request: %w", err)
		}

		// Read response
		response := make([]byte, 1024)
		c.conn.SetReadDeadline(time.Now().Add(c.timeout))
		n, fromAddr, err := c.conn.ReadFromUDP(response)
		if err != nil {
			return nil, fmt.Errorf("failed to read STUN response: %w", err)
		}

		// Verify response is from STUN server
		if !fromAddr.IP.Equal(serverAddr.IP) {
			return nil, fmt.Errorf("response from unexpected address: %v", fromAddr)
		}

		return parseBindingResponse(response[:n], request[8:20])
	}

	// Create new UDP connection if no shared connection
	var conn *net.UDPConn
	if localAddr != nil {
		conn, err = net.DialUDP("udp", localAddr, serverAddr)
	} else {
		conn, err = net.DialUDP("udp", nil, serverAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to STUN server: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(c.timeout))

	// Send request
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("failed to send STUN request: %w", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read STUN response: %w", err)
	}

	// Parse response
	return parseBindingResponse(response[:n], request[8:20])
}

func parseSTUNURI(uri string) (string, error) {
	// Simple parser for stun:host:port format
	if len(uri) > 5 && uri[:5] == "stun:" {
		return uri[5:], nil
	}
	return uri, nil
}

func buildBindingRequest() []byte {
	request := make([]byte, stunHeaderSize)

	// Message Type: Binding Request
	binary.BigEndian.PutUint16(request[0:2], stunBindingRequest)

	// Message Length: 0 (no attributes)
	binary.BigEndian.PutUint16(request[2:4], 0)

	// Magic Cookie
	binary.BigEndian.PutUint32(request[4:8], stunMagicCookie)

	// Transaction ID (12 bytes random)
	for i := 8; i < 20; i++ {
		request[i] = byte(time.Now().UnixNano() >> (i * 8))
	}

	return request
}

func parseBindingResponse(data []byte, transactionID []byte) (*MappedAddress, error) {
	if len(data) < stunHeaderSize {
		return nil, errors.New("response too short")
	}

	// Check message type
	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != stunBindingResponse {
		return nil, fmt.Errorf("unexpected message type: 0x%04x", msgType)
	}

	// Check magic cookie
	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != stunMagicCookie {
		return nil, errors.New("invalid magic cookie")
	}

	// Parse attributes
	msgLen := binary.BigEndian.Uint16(data[2:4])
	attrs := data[stunHeaderSize : stunHeaderSize+int(msgLen)]

	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := binary.BigEndian.Uint16(attrs[2:4])

		if len(attrs) < 4+int(attrLen) {
			break
		}

		attrValue := attrs[4 : 4+attrLen]

		switch attrType {
		case stunAttrXorMappedAddress:
			return parseXorMappedAddress(attrValue, data[4:8], transactionID)
		case stunAttrMappedAddress:
			return parseMappedAddress(attrValue)
		}

		// Move to next attribute (with padding)
		padded := (int(attrLen) + 3) & ^3
		attrs = attrs[4+padded:]
	}

	return nil, errors.New("no mapped address in response")
}

func parseXorMappedAddress(data []byte, magicCookie, transactionID []byte) (*MappedAddress, error) {
	if len(data) < 8 {
		return nil, errors.New("XOR-MAPPED-ADDRESS too short")
	}

	family := data[1]
	xorPort := binary.BigEndian.Uint16(data[2:4])
	port := int(xorPort ^ uint16(magicCookie[0])<<8 ^ uint16(magicCookie[1]))

	var ip net.IP
	if family == 0x01 { // IPv4
		if len(data) < 8 {
			return nil, errors.New("XOR-MAPPED-ADDRESS IPv4 too short")
		}
		ip = make(net.IP, 4)
		for i := 0; i < 4; i++ {
			ip[i] = data[4+i] ^ magicCookie[i]
		}
	} else if family == 0x02 { // IPv6
		if len(data) < 20 {
			return nil, errors.New("XOR-MAPPED-ADDRESS IPv6 too short")
		}
		ip = make(net.IP, 16)
		xorBytes := append(magicCookie, transactionID...)
		for i := 0; i < 16; i++ {
			ip[i] = data[4+i] ^ xorBytes[i]
		}
	} else {
		return nil, fmt.Errorf("unknown address family: %d", family)
	}

	return &MappedAddress{IP: ip, Port: port}, nil
}

func parseMappedAddress(data []byte) (*MappedAddress, error) {
	if len(data) < 8 {
		return nil, errors.New("MAPPED-ADDRESS too short")
	}

	family := data[1]
	port := int(binary.BigEndian.Uint16(data[2:4]))

	var ip net.IP
	if family == 0x01 { // IPv4
		ip = net.IP(data[4:8])
	} else if family == 0x02 { // IPv6
		if len(data) < 20 {
			return nil, errors.New("MAPPED-ADDRESS IPv6 too short")
		}
		ip = net.IP(data[4:20])
	} else {
		return nil, fmt.Errorf("unknown address family: %d", family)
	}

	return &MappedAddress{IP: ip, Port: port}, nil
}
