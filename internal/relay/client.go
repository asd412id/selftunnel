package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Message types for relay protocol
type MessageType string

const (
	MsgTypeAuth     MessageType = "auth"
	MsgTypeData     MessageType = "data"
	MsgTypePing     MessageType = "ping"
	MsgTypePong     MessageType = "pong"
	MsgTypeError    MessageType = "error"
	MsgTypePunch    MessageType = "punch"
	MsgTypePunchAck MessageType = "punch_ack"
)

// RelayMessage is the message format for relay communication
type RelayMessage struct {
	Type          MessageType `json:"type"`
	NetworkID     string      `json:"network_id,omitempty"`
	NetworkSecret string      `json:"network_secret,omitempty"`
	PublicKey     string      `json:"public_key,omitempty"`
	To            string      `json:"to,omitempty"`
	From          string      `json:"from,omitempty"`
	Payload       string      `json:"payload,omitempty"` // base64 encoded
	Error         string      `json:"error,omitempty"`
	Endpoints     string      `json:"endpoints,omitempty"` // comma-separated endpoints for punch
}

// Client is a WebSocket relay client
type Client struct {
	relayURL      string
	networkID     string
	networkSecret string
	publicKey     string

	conn      *websocket.Conn
	connected bool
	connMu    sync.RWMutex
	writeMu   sync.Mutex // Mutex for websocket writes - gorilla/websocket only supports one concurrent writer

	sendCh chan []byte
	recvCh chan *RelayMessage

	onData       func(from string, data []byte)
	onPunch      func(from string, endpoints []string) // callback when peer wants to punch
	onDisconnect func()                                // callback when relay disconnects

	autoReconnect bool // enable auto-reconnect

	ctx struct {
		done chan struct{}
	}
	wg sync.WaitGroup
}

// NewClient creates a new relay client
func NewClient(relayURL, networkID, networkSecret, publicKey string) *Client {
	return &Client{
		relayURL:      relayURL,
		networkID:     networkID,
		networkSecret: networkSecret,
		publicKey:     publicKey,
		sendCh:        make(chan []byte, 1000), // Increased buffer for bursty traffic like SSH
		recvCh:        make(chan *RelayMessage, 1000),
	}
}

// SetDataHandler sets the callback for receiving data
func (c *Client) SetDataHandler(handler func(from string, data []byte)) {
	c.onData = handler
}

// SetPunchHandler sets the callback for punch coordination
func (c *Client) SetPunchHandler(handler func(from string, endpoints []string)) {
	c.onPunch = handler
}

// SetDisconnectHandler sets the callback for when relay disconnects
func (c *Client) SetDisconnectHandler(handler func()) {
	c.onDisconnect = handler
}

// EnableAutoReconnect enables automatic reconnection when relay disconnects
func (c *Client) EnableAutoReconnect(enable bool) {
	c.autoReconnect = enable
}

// RequestPunch sends a punch request to a peer via relay
func (c *Client) RequestPunch(to string, myEndpoints []string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected to relay")
	}

	msg := RelayMessage{
		Type:      MsgTypePunch,
		To:        to,
		Endpoints: joinEndpoints(myEndpoints),
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	select {
	case c.sendCh <- msgBytes:
		return nil
	default:
		return fmt.Errorf("send buffer full")
	}
}

func joinEndpoints(eps []string) string {
	result := ""
	for i, ep := range eps {
		if i > 0 {
			result += ","
		}
		result += ep
	}
	return result
}

func splitEndpoints(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			if current != "" {
				result = append(result, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// Connect establishes connection to the relay server
func (c *Client) Connect() error {
	c.ctx.done = make(chan struct{})

	// Parse URL and convert https to wss
	u, err := url.Parse(c.relayURL)
	if err != nil {
		return fmt.Errorf("invalid relay URL: %w", err)
	}

	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else if u.Scheme == "http" {
		u.Scheme = "ws"
	}

	log.Printf("Connecting to relay: %s", u.String())

	// Connect with timeout
	dialer := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
	}

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to relay: %w", err)
	}

	c.connMu.Lock()
	c.conn = conn
	c.connected = true
	c.connMu.Unlock()

	// Authenticate
	authMsg := RelayMessage{
		Type:          MsgTypeAuth,
		NetworkID:     c.networkID,
		NetworkSecret: c.networkSecret,
		PublicKey:     c.publicKey,
	}

	if err := c.sendMessage(&authMsg); err != nil {
		conn.Close()
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	// Wait for auth response
	_, msg, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	var resp RelayMessage
	if err := json.Unmarshal(msg, &resp); err != nil {
		conn.Close()
		return fmt.Errorf("invalid auth response: %w", err)
	}

	if resp.Type == MsgTypeError {
		conn.Close()
		return fmt.Errorf("auth failed: %s", resp.Error)
	}

	if resp.Type != MsgTypeAuth {
		conn.Close()
		return fmt.Errorf("unexpected response type: %s", resp.Type)
	}

	log.Printf("Connected to relay server, authenticated as %s", c.publicKey[:16])

	// Start reader/writer goroutines
	c.wg.Add(2)
	go c.reader()
	go c.writer()

	// Start keepalive
	c.wg.Add(1)
	go c.keepalive()

	return nil
}

// Close closes the relay connection (does not stop auto-reconnect)
func (c *Client) Close() {
	c.closeInternal(false)
}

// CloseAndStop closes the relay connection and stops auto-reconnect
func (c *Client) CloseAndStop() {
	c.autoReconnect = false
	c.closeInternal(true)
}

func (c *Client) closeInternal(stopAutoReconnect bool) {
	// Signal goroutines to stop
	select {
	case <-c.ctx.done:
		// Already closed
		if !stopAutoReconnect {
			return
		}
	default:
		close(c.ctx.done)
	}

	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connected = false
	c.connMu.Unlock()

	// Wait with timeout to prevent hanging
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown
	case <-time.After(3 * time.Second):
		log.Printf("[Relay] Close timeout, forcing shutdown")
	}
}

// IsConnected returns true if connected to relay
func (c *Client) IsConnected() bool {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.connected
}

// Send sends data to a peer through the relay
func (c *Client) Send(to string, data []byte) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected to relay")
	}

	msg := RelayMessage{
		Type:    MsgTypeData,
		To:      to,
		Payload: base64.StdEncoding.EncodeToString(data),
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Use timeout to avoid blocking forever but also avoid dropping packets
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()

	select {
	case c.sendCh <- msgBytes:
		return nil
	case <-timer.C:
		log.Printf("[Relay] WARNING: send buffer full, packet dropped")
		return fmt.Errorf("send buffer full")
	case <-c.ctx.done:
		return fmt.Errorf("client closed")
	}
}

func (c *Client) sendMessage(msg *RelayMessage) error {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	// Use writeMu to prevent concurrent writes - gorilla/websocket only supports one writer at a time
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return conn.WriteMessage(websocket.TextMessage, msgBytes)
}

func (c *Client) reader() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.done:
			return
		default:
		}

		c.connMu.RLock()
		conn := c.conn
		c.connMu.RUnlock()

		if conn == nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Relay read error: %v", err)
			}
			c.connMu.Lock()
			c.connected = false
			c.connMu.Unlock()

			// Notify about disconnect
			if c.onDisconnect != nil {
				go c.onDisconnect()
			}

			// Trigger auto-reconnect if enabled
			if c.autoReconnect {
				go c.autoReconnectLoop()
			}
			return
		}

		var relayMsg RelayMessage
		if err := json.Unmarshal(msg, &relayMsg); err != nil {
			continue
		}

		switch relayMsg.Type {
		case MsgTypeData:
			if c.onData != nil && relayMsg.From != "" && relayMsg.Payload != "" {
				data, err := base64.StdEncoding.DecodeString(relayMsg.Payload)
				if err == nil {
					c.onData(relayMsg.From, data)
				}
			}
		case MsgTypePunch:
			// Peer is requesting coordinated hole punch
			if c.onPunch != nil && relayMsg.From != "" {
				endpoints := splitEndpoints(relayMsg.Endpoints)
				log.Printf("[Relay] Received punch request from %s with %d endpoints", relayMsg.From[:16], len(endpoints))
				c.onPunch(relayMsg.From, endpoints)
			}
		case MsgTypePunchAck:
			log.Printf("[Relay] Punch request acknowledged for %s", relayMsg.To[:16])
		case MsgTypePong:
			// Keepalive response
		case MsgTypeError:
			log.Printf("Relay error: %s", relayMsg.Error)
		}
	}
}

func (c *Client) writer() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.done:
			return
		case msg := <-c.sendCh:
			c.connMu.RLock()
			conn := c.conn
			c.connMu.RUnlock()

			if conn == nil {
				return
			}

			// Use writeMu to prevent concurrent writes - gorilla/websocket only supports one writer at a time
			c.writeMu.Lock()
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := conn.WriteMessage(websocket.TextMessage, msg)
			c.writeMu.Unlock()

			if err != nil {
				log.Printf("Relay write error: %v", err)
				return
			}
		}
	}
}

func (c *Client) keepalive() {
	defer c.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.done:
			return
		case <-ticker.C:
			if !c.IsConnected() {
				return
			}

			msg := RelayMessage{Type: MsgTypePing}
			msgBytes, _ := json.Marshal(msg)

			select {
			case c.sendCh <- msgBytes:
			default:
			}
		}
	}
}

// Reconnect attempts to reconnect to the relay
func (c *Client) Reconnect() error {
	c.Close()
	time.Sleep(time.Second)
	return c.Connect()
}

// autoReconnectLoop attempts to reconnect with exponential backoff
func (c *Client) autoReconnectLoop() {
	backoff := 2 * time.Second
	maxBackoff := 60 * time.Second
	attempt := 0

	for {
		select {
		case <-c.ctx.done:
			return
		default:
		}

		attempt++
		log.Printf("[Relay] Attempting reconnect (attempt %d)...", attempt)

		// Reset context for new connection
		c.ctx.done = make(chan struct{})

		if err := c.Connect(); err != nil {
			log.Printf("[Relay] Reconnect failed: %v", err)

			// Exponential backoff
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		log.Printf("[Relay] Reconnected successfully after %d attempts", attempt)
		return
	}
}
