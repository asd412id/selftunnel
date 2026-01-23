package signaling

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/selftunnel/selftunnel/internal/mesh"
)

type Client struct {
	baseURL       string
	networkID     string
	networkSecret string
	httpClient    *http.Client
	localPeer     *mesh.Peer
	onPeersUpdate func([]*mesh.Peer)
	lastPeerState map[string]string // FIX: bug.multinode.7 - Cache peer state for diff
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

type RegisterRequest struct {
	NetworkID     string     `json:"network_id"`
	NetworkSecret string     `json:"network_secret"`
	Peer          *mesh.Peer `json:"peer"`
}

type RegisterResponse struct {
	Success   bool   `json:"success"`
	VirtualIP string `json:"virtual_ip"`
	Message   string `json:"message,omitempty"`
}

// SignalingPeer represents peer data from signaling server
type SignalingPeer struct {
	Name      string   `json:"name"`
	PublicKey string   `json:"public_key"`
	VirtualIP string   `json:"virtual_ip"`
	Endpoints []string `json:"endpoints"`
	LastSeen  int64    `json:"last_seen"` // Unix timestamp ms
}

// ToMeshPeer converts SignalingPeer to mesh.Peer
func (sp *SignalingPeer) ToMeshPeer() *mesh.Peer {
	return &mesh.Peer{
		Name:      sp.Name,
		PublicKey: sp.PublicKey,
		VirtualIP: sp.VirtualIP,
		Endpoints: sp.Endpoints,
		LastSeen:  time.UnixMilli(sp.LastSeen),
	}
}

type PeersResponse struct {
	Peers []SignalingPeer `json:"peers"`
}

type ExchangeRequest struct {
	NetworkID     string   `json:"network_id"`
	NetworkSecret string   `json:"network_secret"`
	FromPublicKey string   `json:"from_public_key"`
	ToPublicKey   string   `json:"to_public_key"`
	Endpoints     []string `json:"endpoints"`
}

func NewClient(baseURL, networkID, networkSecret string) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		baseURL:       baseURL,
		networkID:     networkID,
		networkSecret: networkSecret,
		lastPeerState: make(map[string]string), // FIX: bug.multinode.7
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// SetLocalPeer sets the local peer for registration
func (c *Client) SetLocalPeer(peer *mesh.Peer) {
	c.mu.Lock()
	c.localPeer = peer
	c.mu.Unlock()
}

// SetPeersUpdateCallback sets the callback for when peers are updated
func (c *Client) SetPeersUpdateCallback(callback func([]*mesh.Peer)) {
	c.mu.Lock()
	c.onPeersUpdate = callback
	c.mu.Unlock()
}

// Register registers the local peer with the signaling server
func (c *Client) Register() (*RegisterResponse, error) {
	c.mu.RLock()
	localPeer := c.localPeer
	c.mu.RUnlock()

	if localPeer == nil {
		return nil, fmt.Errorf("local peer not set")
	}

	req := RegisterRequest{
		NetworkID:     c.networkID,
		NetworkSecret: c.networkSecret,
		Peer:          localPeer,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/register",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed: %s", string(bodyBytes))
	}

	var result RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetPeers retrieves the list of peers from the signaling server
func (c *Client) GetPeers() ([]*mesh.Peer, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/peers", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Network-ID", c.networkID)
	req.Header.Set("X-Network-Secret", c.networkSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get peers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get peers: %s", string(bodyBytes))
	}

	var result PeersResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert SignalingPeer to mesh.Peer
	peers := make([]*mesh.Peer, len(result.Peers))
	for i, sp := range result.Peers {
		peers[i] = sp.ToMeshPeer()
	}

	return peers, nil
}

// ExchangeEndpoints exchanges endpoints with a specific peer
func (c *Client) ExchangeEndpoints(toPeerPublicKey string, endpoints []string) error {
	c.mu.RLock()
	localPeer := c.localPeer
	c.mu.RUnlock()

	if localPeer == nil {
		return fmt.Errorf("local peer not set")
	}

	req := ExchangeRequest{
		NetworkID:     c.networkID,
		NetworkSecret: c.networkSecret,
		FromPublicKey: localPeer.PublicKey,
		ToPublicKey:   toPeerPublicKey,
		Endpoints:     endpoints,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/exchange",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("failed to exchange endpoints: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("exchange failed: %s", string(bodyBytes))
	}

	return nil
}

// Heartbeat sends a heartbeat to keep the registration alive
func (c *Client) Heartbeat() error {
	c.mu.RLock()
	localPeer := c.localPeer
	c.mu.RUnlock()

	if localPeer == nil {
		return fmt.Errorf("local peer not set")
	}

	req := map[string]interface{}{
		"network_id":     c.networkID,
		"network_secret": c.networkSecret,
		"public_key":     localPeer.PublicKey,
		"endpoints":      localPeer.Endpoints,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/heartbeat",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// Unregister removes the local peer from the signaling server
func (c *Client) Unregister() error {
	c.mu.RLock()
	localPeer := c.localPeer
	c.mu.RUnlock()

	if localPeer == nil {
		return nil
	}

	req := map[string]interface{}{
		"network_id":     c.networkID,
		"network_secret": c.networkSecret,
		"public_key":     localPeer.PublicKey,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/unregister",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("failed to unregister: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// Start starts the background tasks (heartbeat, peer polling)
func (c *Client) Start() {
	// Fetch peers immediately on start (tracked by wait group)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()

		// Use context-aware HTTP request
		ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
		defer cancel()

		select {
		case <-ctx.Done():
			return
		default:
		}

		peers, err := c.GetPeers()
		if err == nil {
			c.mu.RLock()
			callback := c.onPeersUpdate
			c.mu.RUnlock()

			if callback != nil {
				callback(peers)
			}
		}
	}()

	// Start heartbeat
	c.wg.Add(1)
	go c.heartbeatLoop()

	// Start peer polling
	c.wg.Add(1)
	go c.peerPollingLoop()
}

func (c *Client) heartbeatLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.Heartbeat()
		}
	}
}

// FIX: bug.multinode.7 - Only trigger callback for changed peers
func (c *Client) peerPollingLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			peers, err := c.GetPeers()
			if err != nil {
				continue
			}

			// FIX: Filter to only changed or new peers
			changedPeers := c.filterChangedPeers(peers)

			if len(changedPeers) == 0 {
				continue // No changes, skip callback
			}

			c.mu.RLock()
			callback := c.onPeersUpdate
			c.mu.RUnlock()

			if callback != nil {
				callback(changedPeers)
			}
		}
	}
}

// filterChangedPeers returns only peers that are new or have changed endpoints
func (c *Client) filterChangedPeers(peers []*mesh.Peer) []*mesh.Peer {
	c.mu.Lock()
	defer c.mu.Unlock()

	var changed []*mesh.Peer
	newState := make(map[string]string)

	for _, peer := range peers {
		// Create state hash from endpoints
		endpointHash := ""
		for _, ep := range peer.Endpoints {
			endpointHash += ep + ","
		}
		newState[peer.PublicKey] = endpointHash

		// Check if peer is new or endpoints changed
		oldHash, exists := c.lastPeerState[peer.PublicKey]
		if !exists || oldHash != endpointHash {
			changed = append(changed, peer)
		}
	}

	// Update cached state
	c.lastPeerState = newState

	return changed
}

// Stop stops the client and background tasks
func (c *Client) Stop() {
	// Cancel context first to stop goroutines
	c.cancel()

	// Unregister with timeout
	done := make(chan struct{})
	go func() {
		c.Unregister()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		// Unregister timed out, continue anyway
	}

	// Wait for goroutines with timeout
	waitDone := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		// Goroutines didn't stop in time
	}
}
