package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"github.com/selftunnel/selftunnel/internal/config"
	"github.com/selftunnel/selftunnel/internal/crypto"
	"github.com/selftunnel/selftunnel/internal/dns"
	"github.com/selftunnel/selftunnel/internal/mesh"
	"github.com/selftunnel/selftunnel/internal/nat"
	"github.com/selftunnel/selftunnel/internal/relay"
	"github.com/selftunnel/selftunnel/internal/signaling"
	"github.com/selftunnel/selftunnel/internal/tunnel"
)

type Daemon struct {
	cfg         *config.Config
	tun         *tunnel.TUNDevice
	wg          *tunnel.WireGuardTunnel
	nativeWG    *tunnel.NativeWG // Native wireguard-go implementation
	peerManager *mesh.PeerManager
	router      *mesh.Router
	discovery   *mesh.Discovery
	signaling   *signaling.Client
	holePuncher *nat.HolePuncher
	dnsServer   *dns.Server
	relayClient *relay.Client
	punchCoord  *punchCoordinator // FIX: Coordinate punch requests to prevent spam
	ctx         context.Context
	cancel      context.CancelFunc
}

// punchCoordinator manages incoming punch requests to prevent spam and thundering herd
type punchCoordinator struct {
	mu             sync.Mutex
	lastPunch      map[string]time.Time // last punch time per peer
	pendingPunches map[string][]string  // pending endpoints per peer (for coalescing)
	punchQueue     chan string          // queue of peers to punch
	activePunches  int                  // current number of active punch operations
	maxConcurrent  int                  // max concurrent punch operations
	cooldownPeriod time.Duration        // minimum time between punches to same peer
	coalesceWindow time.Duration        // time to wait before processing punch (to coalesce)
	ctx            context.Context
	cancel         context.CancelFunc
	discovery      *mesh.Discovery
	peerManager    *mesh.PeerManager
}

func newPunchCoordinator(ctx context.Context, discovery *mesh.Discovery, pm *mesh.PeerManager) *punchCoordinator {
	pctx, cancel := context.WithCancel(ctx)
	pc := &punchCoordinator{
		lastPunch:      make(map[string]time.Time),
		pendingPunches: make(map[string][]string),
		punchQueue:     make(chan string, 10),  // Buffer up to 10 peers
		maxConcurrent:  2,                      // Only 2 concurrent punch operations
		cooldownPeriod: 15 * time.Second,       // 15s cooldown per peer
		coalesceWindow: 500 * time.Millisecond, // Wait 500ms to coalesce requests
		ctx:            pctx,
		cancel:         cancel,
		discovery:      discovery,
		peerManager:    pm,
	}
	go pc.processQueue()
	return pc
}

// RequestPunch queues a punch request (with coalescing)
func (pc *punchCoordinator) RequestPunch(peerKey string, endpoints []string) bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Check cooldown
	if lastTime, exists := pc.lastPunch[peerKey]; exists {
		if time.Since(lastTime) < pc.cooldownPeriod {
			log.Printf("[PunchCoord] Ignoring punch request for %s - cooldown (%v remaining)",
				peerKey[:16], pc.cooldownPeriod-time.Since(lastTime))
			return false
		}
	}

	// Coalesce endpoints - merge with any pending punch for this peer
	existing := pc.pendingPunches[peerKey]
	merged := mergeEndpoints(existing, endpoints)
	pc.pendingPunches[peerKey] = merged

	// If this is a new punch request (not just adding endpoints), schedule it
	if len(existing) == 0 {
		// Schedule after coalesce window
		go func() {
			select {
			case <-time.After(pc.coalesceWindow):
				select {
				case pc.punchQueue <- peerKey:
				default:
					log.Printf("[PunchCoord] Punch queue full, dropping request for %s", peerKey[:16])
				}
			case <-pc.ctx.Done():
			}
		}()
	}

	return true
}

func (pc *punchCoordinator) processQueue() {
	for {
		select {
		case <-pc.ctx.Done():
			return
		case peerKey := <-pc.punchQueue:
			pc.processPunch(peerKey)
		}
	}
}

func (pc *punchCoordinator) processPunch(peerKey string) {
	pc.mu.Lock()

	// Check if we can start a new punch
	if pc.activePunches >= pc.maxConcurrent {
		// Re-queue for later
		pc.mu.Unlock()
		time.Sleep(1 * time.Second)
		select {
		case pc.punchQueue <- peerKey:
		default:
		}
		return
	}

	// Get and clear pending endpoints
	endpoints := pc.pendingPunches[peerKey]
	delete(pc.pendingPunches, peerKey)

	if len(endpoints) == 0 {
		pc.mu.Unlock()
		return
	}

	// Double-check cooldown (might have changed while in queue)
	if lastTime, exists := pc.lastPunch[peerKey]; exists {
		if time.Since(lastTime) < pc.cooldownPeriod {
			pc.mu.Unlock()
			return
		}
	}

	// Mark as active and update last punch time
	pc.activePunches++
	pc.lastPunch[peerKey] = time.Now()
	pc.mu.Unlock()

	// Get peer info
	peer := pc.peerManager.GetPeer(peerKey)
	if peer == nil {
		pc.mu.Lock()
		pc.activePunches--
		pc.mu.Unlock()
		return
	}

	log.Printf("[PunchCoord] Processing punch to %s with %d endpoints (active: %d/%d)",
		peer.Name, len(endpoints), pc.activePunches, pc.maxConcurrent)

	// Update peer endpoints
	peer.SetEndpoints(endpoints)

	// Only mark as connecting if not already connected
	if peer.GetState() != mesh.PeerStateConnected {
		peer.SetState(mesh.PeerStateConnecting)
	}
	peer.UpdateLastSeen(false)

	// Execute punch
	if err := pc.discovery.ConnectToPeer(peerKey); err != nil {
		log.Printf("[PunchCoord] Failed to connect to %s: %v", peer.Name, err)
	}

	// Release active slot
	pc.mu.Lock()
	pc.activePunches--
	pc.mu.Unlock()
}

func (pc *punchCoordinator) Stop() {
	pc.cancel()
}

// mergeEndpoints merges two endpoint lists, removing duplicates
func mergeEndpoints(existing, new []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, ep := range existing {
		if !seen[ep] {
			seen[ep] = true
			result = append(result, ep)
		}
	}
	for _, ep := range new {
		if !seen[ep] {
			seen[ep] = true
			result = append(result, ep)
		}
	}
	return result
}

// program implements service.Interface for Windows Service support
type program struct {
	daemon       *Daemon
	instanceName string
}

func (p *program) Start(s service.Service) error {
	log.Println("Service starting...")
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	log.Println("Service stopping...")
	if p.daemon != nil {
		p.daemon.Stop()
	}
	return nil
}

func (p *program) run() {
	cfg, err := config.LoadForInstance(p.instanceName)
	if err != nil {
		log.Printf("Failed to load config: %v", err)
		return
	}

	if cfg.NetworkID == "" || cfg.NetworkSecret == "" {
		log.Println("Not configured. Run 'selftunnel init' or 'selftunnel join' first")
		return
	}

	daemon, err := NewDaemon(cfg)
	if err != nil {
		log.Printf("Failed to create daemon: %v", err)
		return
	}
	p.daemon = daemon

	if err := daemon.Start(); err != nil {
		log.Printf("Failed to start daemon: %v", err)
		return
	}

	// Print status periodically
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-daemon.ctx.Done():
			return
		case <-ticker.C:
			daemon.Status()
		}
	}
}

func NewDaemon(cfg *config.Config) (*Daemon, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &Daemon{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (d *Daemon) Start() error {
	log.Println("Starting SelfTunnel daemon...")

	// Initialize hole puncher
	hp, err := nat.NewHolePuncherWithPort(d.cfg.STUNServers, d.cfg.ListenPort)
	if err != nil {
		return fmt.Errorf("failed to create hole puncher: %w", err)
	}
	d.holePuncher = hp

	// Discover public address
	mapped, err := hp.DiscoverPublicAddr()
	if err != nil {
		log.Printf("Warning: Could not discover public address: %v", err)
	} else {
		log.Printf("Public endpoint: %s:%d", mapped.IP, mapped.Port)
	}

	// Parse private key
	privateKey, err := crypto.FromBase64(d.cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Create local peer
	localPeer := &mesh.Peer{
		Name:      d.cfg.NodeName,
		PublicKey: d.cfg.PublicKey,
		VirtualIP: d.cfg.VirtualIP,
		Endpoints: hp.GetEndpoints(),
	}

	// Initialize peer manager
	d.peerManager = mesh.NewPeerManager(localPeer)

	// Initialize router
	d.router = mesh.NewRouter(d.peerManager)

	// Initialize discovery
	d.discovery = mesh.NewDiscovery(d.peerManager, hp)

	// Initialize signaling client
	d.signaling = signaling.NewClient(d.cfg.SignalingURL, d.cfg.NetworkID, d.cfg.NetworkSecret)
	d.signaling.SetLocalPeer(localPeer)

	// Set up peer update callback - runs in separate goroutine to avoid blocking
	d.signaling.SetPeersUpdateCallback(func(peers []*mesh.Peer) {
		// Process in goroutine to avoid blocking signaling loop
		go d.handlePeersUpdate(peers)
	})

	// Register with signaling server
	resp, err := d.signaling.Register()
	if err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}
	log.Printf("Registered with signaling server, Virtual IP: %s", resp.VirtualIP)

	if d.cfg.VirtualIP == "" {
		d.cfg.VirtualIP = resp.VirtualIP
		if err := d.cfg.Save(); err != nil {
			log.Printf("Warning: failed to save config: %v", err)
		}
	}

	// Decide which WireGuard implementation to use
	if d.cfg.UseNativeWG {
		// Use native wireguard-go implementation
		if err := d.startNativeWG(); err != nil {
			log.Printf("Warning: Could not start native WireGuard: %v", err)
			log.Println("Falling back to custom implementation")
			d.cfg.UseNativeWG = false
		}
	}

	// Use custom implementation if native is not enabled or failed
	if !d.cfg.UseNativeWG {
		if err := d.startCustomWG(hp, privateKey); err != nil {
			log.Printf("Warning: Could not start WireGuard: %v", err)
			log.Println("Running in signaling-only mode (no tunnel)")
		}
	}

	// Set up peer connect callback to update WireGuard endpoint
	d.discovery.SetPeerConnectCallback(func(publicKey string, endpoint string) {
		if d.wg != nil {
			pubKey, err := crypto.FromBase64(publicKey)
			if err != nil {
				log.Printf("Failed to decode public key: %v", err)
				return
			}
			if err := d.wg.UpdatePeerEndpoint(pubKey, endpoint); err != nil {
				log.Printf("Failed to update peer endpoint: %v", err)
			} else {
				log.Printf("[P2P] Updated peer endpoint to %s (direct connection)", endpoint)
			}
		}
	})

	// Start background services
	d.signaling.Start()
	d.discovery.Start()

	// Initialize punch coordinator to prevent rush/spam
	d.punchCoord = newPunchCoordinator(d.ctx, d.discovery, d.peerManager)

	// Start DNS server if enabled AND tunnel is running
	// DNS binds to VirtualIP which only exists if TUN interface is created
	if d.cfg.DNSEnabled && (d.tun != nil || d.nativeWG != nil) {
		// Use port 53 if config has old default port
		dnsPort := d.cfg.DNSPort
		if dnsPort == 53530 || dnsPort == 5353 {
			dnsPort = 53 // Override old default to new default
		}

		resolver := dns.NewMeshResolver(d.peerManager)
		dnsConfig := dns.Config{
			Port:   dnsPort,
			Suffix: d.cfg.DNSSuffix,
			BindIP: d.cfg.VirtualIP, // Bind to VPN IP only
		}
		d.dnsServer = dns.NewServer(resolver, dnsConfig)
		if err := d.dnsServer.Start(); err != nil {
			log.Printf("Warning: Could not start DNS server: %v", err)
		}
	} else if d.cfg.DNSEnabled {
		log.Printf("Warning: DNS server not started - no tunnel interface available")
	}

	log.Println("SelfTunnel daemon started successfully")
	return nil
}

// startNativeWG starts the native wireguard-go implementation
func (d *Daemon) startNativeWG() error {
	log.Println("Starting native WireGuard implementation...")

	cfg := tunnel.NativeWGConfig{
		PrivateKey: d.cfg.PrivateKey,
		Address:    fmt.Sprintf("%s/24", d.cfg.VirtualIP),
		ListenPort: d.cfg.ListenPort,
		MTU:        d.cfg.MTU,
	}

	nwg, err := tunnel.NewNativeWG(cfg)
	if err != nil {
		return fmt.Errorf("failed to create native WireGuard: %w", err)
	}

	if err := nwg.Start(); err != nil {
		return fmt.Errorf("failed to start native WireGuard: %w", err)
	}

	d.nativeWG = nwg

	// Add existing peers
	for _, peer := range d.peerManager.GetAllPeers() {
		endpoint := ""
		if len(peer.Endpoints) > 0 {
			endpoint = peer.Endpoints[0]
		}
		if err := nwg.AddPeer(peer.PublicKey, endpoint, []string{peer.VirtualIP + "/32"}); err != nil {
			log.Printf("Warning: Failed to add peer %s to native WG: %v", peer.Name, err)
		}
	}

	log.Println("Native WireGuard started successfully")
	return nil
}

// startCustomWG starts the custom WireGuard implementation with relay support
func (d *Daemon) startCustomWG(hp *nat.HolePuncher, privateKey [32]byte) error {
	// Create TUN device
	tunDev, err := tunnel.NewTUN(tunnel.TUNConfig{
		Name:      "selftunnel",
		VirtualIP: d.cfg.VirtualIP,
		CIDR:      d.cfg.VirtualIP + "/24",
		MTU:       d.cfg.MTU,
	})
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	d.tun = tunDev

	// Configure the TUN interface (set IP address)
	if err := tunDev.ConfigureInterface(); err != nil {
		log.Printf("Warning: Failed to configure TUN interface: %v", err)
		// Don't fail - interface might already be configured
	}

	// Create WireGuard tunnel using the hole puncher's connection
	wg, err := tunnel.NewWireGuardTunnel(tunnel.WireGuardConfig{
		TUN:        tunDev,
		PrivateKey: privateKey,
		ListenPort: d.cfg.ListenPort,
		Conn:       hp.Conn(), // Share the UDP connection with hole puncher
	})
	if err != nil {
		tunDev.Close()
		return fmt.Errorf("failed to create WireGuard tunnel: %w", err)
	}
	d.wg = wg

	// Add existing peers
	for _, peer := range d.peerManager.GetAllPeers() {
		pubKey, _ := crypto.FromBase64(peer.PublicKey)
		endpoint := ""
		if len(peer.Endpoints) > 0 {
			endpoint = peer.Endpoints[0]
		}
		wg.AddPeer(pubKey, endpoint, []string{peer.VirtualIP + "/32"}, peer.PublicKey)
	}

	// Set up data received callback to update peer state
	wg.SetDataReceivedCallback(func(publicKeyB64 string, isDirect bool) {
		peer := d.peerManager.GetPeer(publicKeyB64)
		if peer != nil {
			peer.UpdateLastSeen(false)
			if peer.GetState() != mesh.PeerStateConnected {
				peer.SetState(mesh.PeerStateConnected)
				if isDirect {
					log.Printf("[Data] Peer %s now CONNECTED (direct)", peer.Name)
				} else {
					log.Printf("[Data] Peer %s now CONNECTED (relay)", peer.Name)
				}
			}
		}
	})

	// Set up reconnect callback - triggered when direct connection is stale
	wg.SetNeedReconnectCallback(func(publicKeyB64 string) {
		peer := d.peerManager.GetPeer(publicKeyB64)
		if peer != nil {
			log.Printf("[Reconnect] Attempting to re-establish direct connection to %s", peer.Name)
			// Mark peer for reconnection and trigger discovery
			peer.SetState(mesh.PeerStateConnecting)
			go d.discovery.ConnectToPeer(publicKeyB64)
		}
	})

	if err := wg.Start(); err != nil {
		return fmt.Errorf("failed to start WireGuard tunnel: %w", err)
	}

	log.Println("WireGuard tunnel started")

	// Connect to relay server asynchronously
	go d.connectRelay()

	return nil
}

// connectRelay connects to the relay server asynchronously
func (d *Daemon) connectRelay() {
	relayURL := strings.TrimSuffix(d.cfg.SignalingURL, "/register")
	relayURL = strings.TrimSuffix(relayURL, "/") + "/relay"
	log.Printf("Relay URL: %s", relayURL)

	d.relayClient = relay.NewClient(relayURL, d.cfg.NetworkID, d.cfg.NetworkSecret, d.cfg.PublicKey)

	// Set up relay data handler to forward to WireGuard
	d.relayClient.SetDataHandler(func(from string, data []byte) {
		if d.wg != nil {
			d.wg.WriteFromRelay(from, data)
		}
	})

	// Set up punch coordination handler - uses coordinator to prevent spam
	d.relayClient.SetPunchHandler(func(from string, peerEndpoints []string) {
		// Get the peer and check state first
		peer := d.peerManager.GetPeer(from)
		if peer == nil {
			log.Printf("[Punch] Unknown peer %s, ignoring punch request", from[:16])
			return
		}

		// IMPORTANT: Don't disturb a working direct connection!
		// Only process punch request if peer is not connected or hasn't been seen recently
		currentState := peer.GetState()
		lastSeen := peer.GetLastSeen()

		// More conservative: only retry if truly stale (>60s) or disconnected
		if currentState == mesh.PeerStateConnected && time.Since(lastSeen) < 60*time.Second {
			log.Printf("[Punch] Ignoring punch request from %s - already connected (last seen %v ago)", peer.Name, time.Since(lastSeen).Round(time.Second))
			return
		}

		log.Printf("[Punch] Received coordinated punch request from %s with %d endpoints", peer.Name, len(peerEndpoints))

		// Merge endpoints: use fresh ones from punch request + existing ones
		existingEndpoints := peer.GetEndpoints()
		mergedEndpoints := mergeEndpoints(existingEndpoints, peerEndpoints)

		// Use punch coordinator to handle the request (with rate limiting and coalescing)
		if d.punchCoord != nil {
			d.punchCoord.RequestPunch(from, mergedEndpoints)
		} else {
			// Fallback to direct connection if coordinator not initialized
			peer.SetEndpoints(mergedEndpoints)
			if peer.GetState() != mesh.PeerStateConnected {
				peer.SetState(mesh.PeerStateConnecting)
			}
			peer.UpdateLastSeen(false)
			go d.discovery.ConnectToPeer(from)
		}
	})

	if err := d.relayClient.Connect(); err != nil {
		log.Printf("Warning: Could not connect to relay: %v", err)
	} else {
		log.Println("Connected to relay server (fallback enabled)")
		d.relayClient.EnableAutoReconnect(true) // Enable auto-reconnect
		d.wg.SetRelay(d.relayClient)
		d.discovery.SetRelayClient(d.relayClient) // Enable coordinated hole punching
	}
}

func (d *Daemon) Stop() {
	log.Println("Stopping SelfTunnel daemon...")
	d.cancel()

	// Use a timeout for graceful shutdown
	done := make(chan struct{})
	go func() {
		defer close(done)

		// Stop punch coordinator first
		if d.punchCoord != nil {
			d.punchCoord.Stop()
		}

		if d.dnsServer != nil {
			d.dnsServer.Stop()
		}

		if d.discovery != nil {
			d.discovery.Stop()
		}

		if d.signaling != nil {
			d.signaling.Stop()
		}

		if d.relayClient != nil {
			d.relayClient.CloseAndStop()
		}

		if d.wg != nil {
			d.wg.Stop()
		}

		if d.tun != nil {
			d.tun.Close()
		}

		if d.holePuncher != nil {
			d.holePuncher.Close()
		}
	}()

	// Wait for graceful shutdown with timeout
	select {
	case <-done:
		log.Println("SelfTunnel daemon stopped gracefully")
	case <-time.After(5 * time.Second):
		log.Println("SelfTunnel daemon stopped (timeout)")
	}
}

// handlePeersUpdate processes peer updates from signaling server
// This runs in a separate goroutine to avoid blocking the signaling loop
// FIX: bug.multinode.8 - Added staggering to prevent thundering herd
func (d *Daemon) handlePeersUpdate(peers []*mesh.Peer) {
	log.Printf("Received %d peers from signaling server", len(peers))

	// FIX: Collect new peers and connect with staggered delay
	var newPeers []*mesh.Peer

	for _, peer := range peers {
		keyPreview := peer.PublicKey
		if len(keyPreview) > 16 {
			keyPreview = keyPreview[:16]
		}
		log.Printf("  Peer: %s (%s) - %s...", peer.Name, peer.VirtualIP, keyPreview)

		if peer.PublicKey == d.cfg.PublicKey {
			continue
		}

		existing := d.peerManager.GetPeer(peer.PublicKey)
		if existing == nil {
			// Initialize LastSeen to now when adding new peer
			// This prevents false "stale connection" detection
			peer.LastSeen = time.Now()
			d.peerManager.AddPeer(peer)
			log.Printf("New peer discovered: %s (%s)", peer.Name, peer.VirtualIP)

			// Add hosts file entry for DNS resolution (Windows)
			tunnel.UpdateHostsForPeer(peer.Name, peer.VirtualIP, d.cfg.DNSSuffix)

			// Add to WireGuard if tunnel is running
			if d.wg != nil {
				pubKey, _ := crypto.FromBase64(peer.PublicKey)
				endpoint := ""
				if len(peer.Endpoints) > 0 {
					endpoint = peer.Endpoints[0]
				}
				if err := d.wg.AddPeer(pubKey, endpoint, []string{peer.VirtualIP + "/32"}, peer.PublicKey); err != nil {
					log.Printf("Warning: Failed to add peer %s to WireGuard: %v", peer.Name, err)
				} else {
					log.Printf("Added peer %s to WireGuard (endpoint: %s, allowedIP: %s/32)", peer.Name, endpoint, peer.VirtualIP)
				}
			}

			// FIX: Collect new peers instead of immediate connection
			newPeers = append(newPeers, peer)
		} else {
			// Update existing peer's endpoints if changed
			endpointChanged := existing.SetEndpoints(peer.Endpoints)

			// If primary endpoint changed and peer was connected, trigger reconnect
			// This handles IP change scenarios (NAT rebinding, network switch, etc.)
			if endpointChanged {
				currentState := existing.GetState()
				lastSeen := existing.GetLastSeen()

				// Only trigger reconnect if connection seems stale (no data in 5+ seconds)
				// This avoids unnecessary reconnects when connection is still working
				if currentState == mesh.PeerStateConnected && time.Since(lastSeen) > 5*time.Second {
					log.Printf("[Endpoint] Peer %s endpoint changed and connection stale, triggering reconnect", existing.Name)
					existing.SetState(mesh.PeerStateConnecting)

					// Enable relay fallback and update WireGuard endpoint immediately
					if d.wg != nil && len(peer.Endpoints) > 0 {
						d.wg.EnableRelayFallback(existing.PublicKey)
						d.wg.UpdatePeerEndpointByKey(existing.PublicKey, peer.Endpoints[0])
					}

					// Attempt new direct connection (don't add to stagger queue - this is a reconnect)
					if d.discovery != nil {
						go d.discovery.ConnectToPeer(peer.PublicKey)
					}
				} else if currentState != mesh.PeerStateConnected {
					// Peer not connected, update endpoint and try to connect
					log.Printf("[Endpoint] Peer %s endpoint changed (state: %v), updating", existing.Name, currentState)
					if d.wg != nil && len(peer.Endpoints) > 0 {
						d.wg.UpdatePeerEndpointByKey(existing.PublicKey, peer.Endpoints[0])
					}
				}
			}
		}
	}

	// FIX: bug.multinode.8 - Staggered connection for new peers
	if len(newPeers) > 0 && d.discovery != nil {
		go func() {
			for i, peer := range newPeers {
				// First peer immediate, subsequent peers with 1s delay
				if i > 0 {
					time.Sleep(1 * time.Second)
				}
				d.discovery.ConnectToPeer(peer.PublicKey)
			}
		}()
	}
}

func (d *Daemon) Status() {
	log.Println("Daemon Status:")
	log.Printf("  Node: %s", d.cfg.NodeName)
	log.Printf("  Virtual IP: %s", d.cfg.VirtualIP)
	log.Printf("  Network: %s", d.cfg.NetworkID)

	if d.tun != nil {
		log.Printf("  TUN Interface: %s", d.tun.Name())
	}

	relayStatus := "disconnected"
	if d.relayClient != nil && d.relayClient.IsConnected() {
		relayStatus = "connected"
	}
	log.Printf("  Relay: %s", relayStatus)

	if d.dnsServer != nil {
		dnsPort := d.cfg.DNSPort
		if dnsPort == 53530 || dnsPort == 5353 {
			dnsPort = 53
		}
		log.Printf("  DNS: %s.%s -> %s (port %d)", d.cfg.NodeName, d.cfg.DNSSuffix, d.cfg.VirtualIP, dnsPort)
	}

	peers := d.peerManager.GetAllPeers()
	log.Printf("  Peers: %d", len(peers))
	for _, p := range peers {
		state := "disconnected"
		// Use GetState() for thread-safe access (bug fix: race_condition.4)
		peerState := p.GetState()
		if peerState == mesh.PeerStateConnected {
			state = "connected"
		} else if peerState == mesh.PeerStateConnecting {
			state = "connecting"
		}
		log.Printf("    - %s (%s): %s", p.Name, p.VirtualIP, state)
	}
}

// RunDaemon runs the daemon, supporting both interactive and service modes
func RunDaemon(instanceName string) error {
	// Create service config
	svcName := "selftunnel"
	if instanceName != "" {
		svcName = fmt.Sprintf("selftunnel-%s", instanceName)
	}

	svcConfig := &service.Config{
		Name:        svcName,
		DisplayName: "SelfTunnel P2P Mesh VPN",
		Description: "Peer-to-peer mesh VPN service",
	}

	prg := &program{
		instanceName: instanceName,
	}

	s, err := service.New(prg, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	// Check if running interactively
	if service.Interactive() {
		// Running from command line, not as service
		return runInteractive(instanceName)
	}

	// Running as service
	return s.Run()
}

// runInteractive runs the daemon in interactive/foreground mode
func runInteractive(instanceName string) error {
	cfg, err := config.LoadForInstance(instanceName)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.NetworkID == "" || cfg.NetworkSecret == "" {
		return fmt.Errorf("not configured. Run 'selftunnel init' or 'selftunnel join' first")
	}

	daemon, err := NewDaemon(cfg)
	if err != nil {
		return err
	}

	if err := daemon.Start(); err != nil {
		return err
	}

	// Print status periodically
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-daemon.ctx.Done():
				return
			case <-ticker.C:
				daemon.Status()
			}
		}
	}()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	daemon.Stop()
	return nil
}
