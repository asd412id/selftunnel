package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Peer represents a registered peer
type Peer struct {
	Name      string            `json:"name"`
	PublicKey string            `json:"public_key"`
	VirtualIP string            `json:"virtual_ip"`
	Endpoints []string          `json:"endpoints"`
	LastSeen  int64             `json:"last_seen"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// PeerInput is used for parsing incoming peer data (accepts various last_seen formats)
type PeerInput struct {
	Name      string            `json:"name"`
	PublicKey string            `json:"public_key"`
	VirtualIP string            `json:"virtual_ip"`
	Endpoints []string          `json:"endpoints"`
	LastSeen  interface{}       `json:"last_seen,omitempty"` // Can be int64, string, or omitted
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Network represents a network with its peers
type Network struct {
	ID         string           `json:"id"`
	SecretHash string           `json:"secret_hash"`
	Peers      map[string]*Peer `json:"peers"`
	NextIP     int              `json:"next_ip"`
	CreatedAt  int64            `json:"created_at"`
	mu         sync.RWMutex
}

// RelayMessage is the WebSocket relay message format
type RelayMessage struct {
	Type          string `json:"type"`
	NetworkID     string `json:"network_id,omitempty"`
	NetworkSecret string `json:"network_secret,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
	To            string `json:"to,omitempty"`
	From          string `json:"from,omitempty"`
	Payload       string `json:"payload,omitempty"`
	Error         string `json:"error,omitempty"`
	Endpoints     string `json:"endpoints,omitempty"` // For punch coordination
}

// Server is the signaling server
type Server struct {
	networks    map[string]*Network
	networksMu  sync.RWMutex
	connections map[string]map[string]*websocket.Conn // networkID -> publicKey -> conn
	connMu      sync.RWMutex
	upgrader    websocket.Upgrader
	peerTTL     time.Duration
}

// NewServer creates a new signaling server
func NewServer() *Server {
	return &Server{
		networks:    make(map[string]*Network),
		connections: make(map[string]map[string]*websocket.Conn),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// Allow connections without Origin header (non-browser clients like CLI tools)
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true
				}
				// Allow localhost for development
				if strings.HasPrefix(origin, "http://localhost") ||
					strings.HasPrefix(origin, "https://localhost") ||
					strings.HasPrefix(origin, "http://127.0.0.1") ||
					strings.HasPrefix(origin, "https://127.0.0.1") {
					return true
				}
				// Allow same-origin requests
				host := r.Host
				if strings.Contains(origin, host) {
					return true
				}
				// Reject cross-origin browser requests to prevent CSRF
				log.Printf("[Security] Rejected WebSocket connection from origin: %s (host: %s)", origin, host)
				return false
			},
		},
		peerTTL: 5 * time.Minute,
	}
}

func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return base64.StdEncoding.EncodeToString(h[:])
}

// RegisterRequest is the request body for /register
type RegisterRequest struct {
	NetworkID     string     `json:"network_id"`
	NetworkSecret string     `json:"network_secret"`
	Peer          *PeerInput `json:"peer"`
}

// RegisterResponse is the response for /register
type RegisterResponse struct {
	Success   bool   `json:"success"`
	VirtualIP string `json:"virtual_ip,omitempty"`
	Message   string `json:"message,omitempty"`
}

// PeersResponse is the response for /peers
type PeersResponse struct {
	Peers []*Peer `json:"peers"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Register decode error: %v", err)
		writeJSON(w, http.StatusBadRequest, RegisterResponse{Success: false, Message: "Invalid request"})
		return
	}

	if req.Peer == nil || req.Peer.PublicKey == "" || req.Peer.Name == "" {
		log.Printf("Register missing data: peer=%v", req.Peer)
		writeJSON(w, http.StatusBadRequest, RegisterResponse{Success: false, Message: "Missing peer data"})
		return
	}

	secretHash := hashSecret(req.NetworkSecret)

	s.networksMu.Lock()
	network, exists := s.networks[req.NetworkID]
	if !exists {
		network = &Network{
			ID:         req.NetworkID,
			SecretHash: secretHash,
			Peers:      make(map[string]*Peer),
			NextIP:     2,
			CreatedAt:  time.Now().UnixMilli(),
		}
		s.networks[req.NetworkID] = network
	}
	s.networksMu.Unlock()

	network.mu.Lock()
	defer network.mu.Unlock()

	// Validate secret
	if network.SecretHash != secretHash {
		writeJSON(w, http.StatusUnauthorized, RegisterResponse{Success: false, Message: "Invalid credentials"})
		return
	}

	// Cleanup stale peers
	s.cleanupStalePeers(network)

	// Allocate or reuse IP
	var virtualIP string

	// Check if this peer already has an IP assigned (by public key)
	if existingPeer, ok := network.Peers[req.Peer.PublicKey]; ok {
		virtualIP = existingPeer.VirtualIP
	} else {
		// Check if the requested IP is available
		requestedIP := req.Peer.VirtualIP
		if requestedIP != "" && !isIPInUse(network, requestedIP, req.Peer.PublicKey) {
			virtualIP = requestedIP
		} else {
			// Allocate a new unique IP
			virtualIP = allocateUniqueIP(network)
		}
	}

	// Check if name is already in use by another peer
	for pk, existingPeer := range network.Peers {
		if pk != req.Peer.PublicKey && strings.EqualFold(existingPeer.Name, req.Peer.Name) {
			// Note: defer handles unlock, so just return after writing response
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": fmt.Sprintf("Node name '%s' is already in use by another peer. Please use a unique name.", req.Peer.Name),
			})
			return
		}
	}

	network.Peers[req.Peer.PublicKey] = &Peer{
		Name:      req.Peer.Name,
		PublicKey: req.Peer.PublicKey,
		VirtualIP: virtualIP,
		Endpoints: req.Peer.Endpoints,
		LastSeen:  time.Now().UnixMilli(),
		Metadata:  req.Peer.Metadata,
	}

	log.Printf("[%s] Registered peer: %s (%s) - %s", truncate(req.NetworkID, 8), req.Peer.Name, virtualIP, truncate(req.Peer.PublicKey, 16))

	writeJSON(w, http.StatusOK, RegisterResponse{Success: true, VirtualIP: virtualIP})
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	networkID := r.Header.Get("X-Network-ID")
	networkSecret := r.Header.Get("X-Network-Secret")

	if networkID == "" || networkSecret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing credentials"})
		return
	}

	secretHash := hashSecret(networkSecret)

	s.networksMu.RLock()
	network, exists := s.networks[networkID]
	s.networksMu.RUnlock()

	if !exists || network.SecretHash != secretHash {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}

	network.mu.Lock()
	s.cleanupStalePeers(network)
	peers := make([]*Peer, 0, len(network.Peers))
	for _, p := range network.Peers {
		peers = append(peers, p)
	}
	network.mu.Unlock()

	writeJSON(w, http.StatusOK, PeersResponse{Peers: peers})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NetworkID     string   `json:"network_id"`
		NetworkSecret string   `json:"network_secret"`
		PublicKey     string   `json:"public_key"`
		Endpoints     []string `json:"endpoints"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]bool{"success": false})
		return
	}

	secretHash := hashSecret(req.NetworkSecret)

	s.networksMu.RLock()
	network, exists := s.networks[req.NetworkID]
	s.networksMu.RUnlock()

	if !exists || network.SecretHash != secretHash {
		writeJSON(w, http.StatusUnauthorized, map[string]bool{"success": false})
		return
	}

	network.mu.Lock()
	if peer, ok := network.Peers[req.PublicKey]; ok {
		peer.LastSeen = time.Now().UnixMilli()
		if len(req.Endpoints) > 0 {
			peer.Endpoints = req.Endpoints
		}
	}
	network.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleUnregister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NetworkID     string `json:"network_id"`
		NetworkSecret string `json:"network_secret"`
		PublicKey     string `json:"public_key"`
		PeerName      string `json:"peer_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]bool{"success": false})
		return
	}

	secretHash := hashSecret(req.NetworkSecret)

	s.networksMu.RLock()
	network, exists := s.networks[req.NetworkID]
	s.networksMu.RUnlock()

	if !exists || network.SecretHash != secretHash {
		writeJSON(w, http.StatusUnauthorized, map[string]bool{"success": false})
		return
	}

	network.mu.Lock()
	// Support unregister by public_key or peer_name
	if req.PublicKey != "" {
		delete(network.Peers, req.PublicKey)
	} else if req.PeerName != "" {
		for k, p := range network.Peers {
			if p.Name == req.PeerName {
				delete(network.Peers, k)
				break
			}
		}
	}
	network.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleRelay(w http.ResponseWriter, r *http.Request) {
	// Get network ID from query or header
	networkID := r.URL.Query().Get("network_id")
	if networkID == "" {
		networkID = r.Header.Get("X-Network-ID")
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	var authenticated bool
	var publicKey string
	var currentNetworkID string

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var relayMsg RelayMessage
		if err := json.Unmarshal(msg, &relayMsg); err != nil {
			conn.WriteJSON(RelayMessage{Type: "error", Error: "Invalid message format"})
			continue
		}

		switch relayMsg.Type {
		case "auth":
			if relayMsg.NetworkSecret == "" || relayMsg.PublicKey == "" {
				conn.WriteJSON(RelayMessage{Type: "error", Error: "Missing auth fields"})
				continue
			}

			secretHash := hashSecret(relayMsg.NetworkSecret)
			netID := relayMsg.NetworkID
			if netID == "" {
				netID = networkID
			}

			s.networksMu.RLock()
			network, exists := s.networks[netID]
			s.networksMu.RUnlock()

			if !exists || network.SecretHash != secretHash {
				conn.WriteJSON(RelayMessage{Type: "error", Error: "Invalid credentials"})
				conn.Close()
				return
			}

			authenticated = true
			publicKey = relayMsg.PublicKey
			currentNetworkID = netID

			// Store connection
			s.connMu.Lock()
			if s.connections[currentNetworkID] == nil {
				s.connections[currentNetworkID] = make(map[string]*websocket.Conn)
			}
			s.connections[currentNetworkID][publicKey] = conn
			s.connMu.Unlock()

			log.Printf("[%s] Relay connected: %s", truncate(currentNetworkID, 8), truncate(publicKey, 16))
			conn.WriteJSON(RelayMessage{Type: "auth", PublicKey: publicKey})

		case "data":
			if !authenticated {
				conn.WriteJSON(RelayMessage{Type: "error", Error: "Not authenticated"})
				continue
			}

			if relayMsg.To == "" || relayMsg.Payload == "" {
				conn.WriteJSON(RelayMessage{Type: "error", Error: "Missing to or payload"})
				continue
			}

			// Forward to target
			s.connMu.RLock()
			targetConn := s.connections[currentNetworkID][relayMsg.To]
			s.connMu.RUnlock()

			if targetConn != nil {
				err := targetConn.WriteJSON(RelayMessage{
					Type:    "data",
					From:    publicKey,
					Payload: relayMsg.Payload,
				})
				if err != nil {
					log.Printf("[%s] Relay data forward failed: %s -> %s: %v",
						truncate(currentNetworkID, 8), truncate(publicKey, 16), truncate(relayMsg.To, 16), err)
				}
			} else {
				// Target not connected - log for debugging
				log.Printf("[%s] Relay data dropped: %s -> %s (target not connected)",
					truncate(currentNetworkID, 8), truncate(publicKey, 16), truncate(relayMsg.To, 16))
			}

		case "punch":
			// Punch coordination: forward punch request to peer
			// When peer receives this, both should start hole punching simultaneously
			if !authenticated {
				conn.WriteJSON(RelayMessage{Type: "error", Error: "Not authenticated"})
				continue
			}

			if relayMsg.To == "" {
				conn.WriteJSON(RelayMessage{Type: "error", Error: "Missing target peer"})
				continue
			}

			// Forward punch request to target with sender's endpoints
			s.connMu.RLock()
			targetConn := s.connections[currentNetworkID][relayMsg.To]
			s.connMu.RUnlock()

			if targetConn != nil {
				targetConn.WriteJSON(RelayMessage{
					Type:      "punch",
					From:      publicKey,
					Endpoints: relayMsg.Endpoints,
				})
				// Send confirmation back to sender
				conn.WriteJSON(RelayMessage{
					Type: "punch_ack",
					To:   relayMsg.To,
				})
				log.Printf("[%s] Punch coordination: %s -> %s", truncate(currentNetworkID, 8), truncate(publicKey, 16), truncate(relayMsg.To, 16))
			} else {
				conn.WriteJSON(RelayMessage{Type: "error", Error: "Target peer not connected to relay"})
			}

		case "ping":
			conn.WriteJSON(RelayMessage{Type: "pong"})
		}
	}

	// Cleanup on disconnect
	if authenticated && currentNetworkID != "" && publicKey != "" {
		s.connMu.Lock()
		if s.connections[currentNetworkID] != nil {
			delete(s.connections[currentNetworkID], publicKey)
		}
		s.connMu.Unlock()
		log.Printf("[%s] Relay disconnected: %s", truncate(currentNetworkID, 8), truncate(publicKey, 16))
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.networksMu.RLock()
	networkCount := len(s.networks)
	s.networksMu.RUnlock()

	s.connMu.RLock()
	relayCount := 0
	for _, conns := range s.connections {
		relayCount += len(conns)
	}
	s.connMu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"service":  "selftunnel-signaling",
		"version":  "2.0.0",
		"features": []string{"signaling", "relay", "websocket"},
		"stats": map[string]int{
			"networks":          networkCount,
			"relay_connections": relayCount,
		},
	})
}

func (s *Server) cleanupStalePeers(network *Network) {
	now := time.Now().UnixMilli()
	ttlMs := s.peerTTL.Milliseconds()
	for k, p := range network.Peers {
		if now-p.LastSeen > ttlMs {
			delete(network.Peers, k)
			log.Printf("[%s] Removed stale peer: %s", truncate(network.ID, 8), p.Name)
		}
	}
}

func allocateIP(network *Network) string {
	ip := network.NextIP
	network.NextIP++
	if network.NextIP > 254 {
		network.NextIP = 2
	}
	return "10.99.0." + itoa(ip)
}

// isIPInUse checks if an IP is already used by another peer
func isIPInUse(network *Network, ip string, excludePublicKey string) bool {
	for pubKey, peer := range network.Peers {
		if pubKey != excludePublicKey && peer.VirtualIP == ip {
			return true
		}
	}
	return false
}

// allocateUniqueIP allocates a unique IP that's not in use
func allocateUniqueIP(network *Network) string {
	for i := 0; i < 253; i++ {
		ip := "10.99.0." + itoa(network.NextIP)
		network.NextIP++
		if network.NextIP > 254 {
			network.NextIP = 2
		}
		if !isIPInUse(network, ip, "") {
			return ip
		}
	}
	// Fallback (should never happen with <253 peers)
	return allocateIP(network)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [10]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

// truncate safely truncates a string to maxLen
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Network-ID, X-Network-Secret")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Network-ID, X-Network-Secret")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func main() {
	port := flag.String("port", "8080", "Server port")
	flag.Parse()

	server := NewServer()

	// Start cleanup routine
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			server.networksMu.Lock()
			for _, network := range server.networks {
				network.mu.Lock()
				server.cleanupStalePeers(network)
				network.mu.Unlock()
			}
			server.networksMu.Unlock()
		}
	}()

	http.HandleFunc("/", corsMiddleware(server.handleHealth))
	http.HandleFunc("/health", corsMiddleware(server.handleHealth))
	http.HandleFunc("/register", corsMiddleware(server.handleRegister))
	http.HandleFunc("/peers", corsMiddleware(server.handlePeers))
	http.HandleFunc("/heartbeat", corsMiddleware(server.handleHeartbeat))
	http.HandleFunc("/unregister", corsMiddleware(server.handleUnregister))
	http.HandleFunc("/relay", server.handleRelay)

	log.Printf("SelfTunnel Signaling Server starting on :%s", *port)
	log.Printf("Endpoints: /register, /peers, /heartbeat, /unregister, /relay")

	if err := http.ListenAndServe(":"+*port, nil); err != nil {
		log.Fatal(err)
	}
}
