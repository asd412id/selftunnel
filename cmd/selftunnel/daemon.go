package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"github.com/selftunnel/selftunnel/internal/config"
	"github.com/selftunnel/selftunnel/internal/crypto"
	"github.com/selftunnel/selftunnel/internal/dns"
	"github.com/selftunnel/selftunnel/internal/mesh"
	"github.com/selftunnel/selftunnel/internal/nat"
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
		for _, peer := range peers {
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
					d.wg.AddPeer(pubKey, endpoint, []string{peer.VirtualIP + "/32"})
				}
			}
		}
		d.router.UpdateRoutesFromPeers()
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
		Name:      "selftun0",
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

		// Create WireGuard tunnel
		wgCfg := tunnel.WireGuardConfig{
			TUN:        tun,
			PrivateKey: privateKey,
			ListenPort: d.cfg.ListenPort,
		}

		wg, err := tunnel.NewWireGuardTunnel(wgCfg)
		if err != nil {
			log.Printf("Warning: Could not create WireGuard tunnel: %v", err)
		} else {
			d.wg = wg
			if err := wg.Start(); err != nil {
				log.Printf("Warning: Could not start WireGuard tunnel: %v", err)
			} else {
				log.Println("WireGuard tunnel started")
			}
		}
	}

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
