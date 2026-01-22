package nat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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

type STUNClient struct {
	servers []string
	timeout time.Duration
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

// GetMappedAddress queries STUN servers to get the public IP and port
func (c *STUNClient) GetMappedAddress(localAddr *net.UDPAddr) (*MappedAddress, error) {
	var lastErr error

	for _, server := range c.servers {
		addr, err := c.queryServer(server, localAddr)
		if err != nil {
			lastErr = err
			continue
		}
		return addr, nil
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

	// Create UDP connection from local address
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

	// Build STUN binding request
	request := buildBindingRequest()

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
