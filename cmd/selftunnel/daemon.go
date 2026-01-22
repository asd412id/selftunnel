package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
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
	peerManager *mesh.PeerManager
	router      *mesh.Router
	discovery   *mesh.Discovery
	signaling   *signaling.Client
	holePuncher *nat.HolePuncher
	dnsServer   *dns.Server
	relayClient *relay.Client
	ctx         context.Context
	cancel      context.CancelFunc
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

	// Set up peer update callback
	d.signaling.SetPeersUpdateCallback(func(peers []*mesh.Peer) {
		log.Printf("Received %d peers from signaling server", len(peers))
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
				d.peerManager.AddPeer(peer)
				log.Printf("New peer discovered: %s (%s)", peer.Name, peer.VirtualIP)

				// Add to WireGuard if tunnel is running
				if d.wg != nil {
					pubKey, _ := crypto.FromBase64(peer.PublicKey)
					endpoint := ""
					if len(peer.Endpoints) > 0 {
						endpoint = peer.Endpoints[0]
					}
					d.wg.AddPeer(pubKey, endpoint, []string{peer.VirtualIP + "/32"}, peer.PublicKey)
				}
			} else {
				// Update existing peer's endpoints if changed
				existing.SetEndpoints(peer.Endpoints)
			}
		}
		// NOTE: Don't call router.UpdateRoutesFromPeers() here - it disrupts active connections
		// WireGuard handles routing via AllowedIPs
	})

	// Register with signaling server
	resp, err := d.signaling.Register()
	if err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}
	log.Printf("Registered with signaling server, Virtual IP: %s", resp.VirtualIP)

	if d.cfg.VirtualIP == "" {
		d.cfg.VirtualIP = resp.VirtualIP
		d.cfg.Save()
	}

	// Create TUN device
	tunCfg := tunnel.TUNConfig{
		Name:      "SelfTunnel",
		MTU:       d.cfg.MTU,
		VirtualIP: d.cfg.VirtualIP,
		CIDR:      d.cfg.VirtualCIDR,
	}

	tun, err := tunnel.NewTUN(tunCfg)
	if err != nil {
		log.Printf("Warning: Could not create TUN device: %v", err)
		log.Println("Running in signaling-only mode (no tunnel)")
	} else {
		d.tun = tun
		log.Printf("Created TUN interface: %s", tun.Name())

		// Configure the interface (set IP, bring up, add routes)
		if err := tun.ConfigureInterface(); err != nil {
			log.Printf("Warning: Could not configure TUN interface: %v", err)
		} else {
			log.Printf("Configured TUN interface with IP %s", d.cfg.VirtualIP)
		}

		// Create WireGuard tunnel using shared connection from HolePuncher
		wgCfg := tunnel.WireGuardConfig{
			TUN:        tun,
			PrivateKey: privateKey,
			ListenPort: d.cfg.ListenPort,
			Conn:       hp.Conn(), // Share UDP connection with HolePuncher
		}

		wg, err := tunnel.NewWireGuardTunnel(wgCfg)
		if err != nil {
			log.Printf("Warning: Could not create WireGuard tunnel: %v", err)
		} else {
			d.wg = wg

			// Track punch count to avoid log spam
			var punchCount int
			var lastPunchAddr string

			// Set up punch packet callback - when WG receives punch, update the peer endpoint
			wg.SetPunchCallback(func(addr *net.UDPAddr) {
				// Ignore punch from virtual IP range (10.99.0.0/24)
				ip4 := addr.IP.To4()
				if ip4 != nil && ip4[0] == 10 && ip4[1] == 99 {
					return
				}

				// Ignore punch from our own public IPs
				myEndpoints := d.holePuncher.GetEndpoints()
				for _, ep := range myEndpoints {
					if ep == addr.String() {
						return
					}
				}

				punchCount++
				addrStr := addr.String()

				// Only log first punch from new address or every 1000 punches
				if addrStr != lastPunchAddr {
					log.Printf("[Punch] Receiving punches from %s", addr)
					lastPunchAddr = addrStr
				}

				// Find peer and update their endpoint
				peers := d.peerManager.GetAllPeers()
				for _, peer := range peers {
					// Update any peer that isn't connected yet
					if peer.State != mesh.PeerStateConnected {
						pubKey := peer.PublicKey
						peerPubKey, err := crypto.FromBase64(pubKey)
						if err == nil {
							d.wg.UpdatePeerEndpoint(peerPubKey, addr.String())
							// Mark peer as connected
							if peer.State != mesh.PeerStateConnected {
								peer.State = mesh.PeerStateConnected
								log.Printf("[Punch] Peer %s CONNECTED via %s", peer.Name, addr)
							}
						}
						break
					}
				}
			})

			// Set up data received callback - update mesh peer LastSeen
			wg.SetDataReceivedCallback(func(publicKeyB64 string, isDirect bool) {
				peer := d.peerManager.GetPeer(publicKeyB64)
				if peer != nil {
					wasConnected := peer.GetState() == mesh.PeerStateConnected
					peer.UpdateLastSeen(true) // Update LastSeen and set connected
					if !wasConnected {
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
				log.Printf("Warning: Could not start WireGuard tunnel: %v", err)
			} else {
				log.Println("WireGuard tunnel started")

				// Connect to relay server asynchronously
				go d.connectRelay()
			}
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

	// Start DNS server if enabled
	if d.cfg.DNSEnabled {
		resolver := dns.NewMeshResolver(d.peerManager)
		dnsConfig := dns.Config{
			Port:   d.cfg.DNSPort,
			Suffix: d.cfg.DNSSuffix,
		}
		d.dnsServer = dns.NewServer(resolver, dnsConfig)
		if err := d.dnsServer.Start(); err != nil {
			log.Printf("Warning: Could not start DNS server: %v", err)
		}
	}

	log.Println("SelfTunnel daemon started successfully")
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

	// Set up punch coordination handler
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

		if currentState == mesh.PeerStateConnected && time.Since(lastSeen) < 30*time.Second {
			log.Printf("[Punch] Ignoring punch request from %s - already connected (last seen %v ago)", peer.Name, time.Since(lastSeen))
			return
		}

		log.Printf("[Punch] Received coordinated punch request from %s with %d endpoints", peer.Name, len(peerEndpoints))

		// Merge endpoints: use fresh ones from punch request + existing ones
		existingEndpoints := peer.GetEndpoints()
		mergedEndpoints := peerEndpoints
		for _, ep := range existingEndpoints {
			found := false
			for _, pep := range peerEndpoints {
				if ep == pep {
					found = true
					break
				}
			}
			if !found {
				mergedEndpoints = append(mergedEndpoints, ep)
			}
		}
		peer.SetEndpoints(mergedEndpoints)
		log.Printf("[Punch] Merged %d endpoints for peer %s", len(mergedEndpoints), peer.Name)

		// Mark peer as connecting so we accept incoming punch
		peer.SetState(mesh.PeerStateConnecting)

		// Start hole punching in background
		go d.discovery.ConnectToPeer(from)
	})

	if err := d.relayClient.Connect(); err != nil {
		log.Printf("Warning: Could not connect to relay: %v", err)
	} else {
		log.Println("Connected to relay server (fallback enabled)")
		d.wg.SetRelay(d.relayClient)
		d.discovery.SetRelayClient(d.relayClient) // Enable coordinated hole punching
	}
}

func (d *Daemon) Stop() {
	log.Println("Stopping SelfTunnel daemon...")
	d.cancel()

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
		d.relayClient.Close()
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

	log.Println("SelfTunnel daemon stopped")
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
		log.Printf("  DNS: %s.%s -> %s (port %d)", d.cfg.NodeName, d.cfg.DNSSuffix, d.cfg.VirtualIP, d.cfg.DNSPort)
	}

	peers := d.peerManager.GetAllPeers()
	log.Printf("  Peers: %d", len(peers))
	for _, p := range peers {
		state := "disconnected"
		if p.State == mesh.PeerStateConnected {
			state = "connected"
		} else if p.State == mesh.PeerStateConnecting {
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
