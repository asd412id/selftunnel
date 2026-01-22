package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/selftunnel/selftunnel/internal/config"
	"github.com/selftunnel/selftunnel/internal/crypto"
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
	ctx         context.Context
	cancel      context.CancelFunc
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

	log.Println("SelfTunnel daemon started successfully")
	return nil
}

func (d *Daemon) Stop() {
	log.Println("Stopping SelfTunnel daemon...")
	d.cancel()

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
	fmt.Println("Daemon Status:")
	fmt.Printf("  Node: %s\n", d.cfg.NodeName)
	fmt.Printf("  Virtual IP: %s\n", d.cfg.VirtualIP)
	fmt.Printf("  Network: %s\n", d.cfg.NetworkID)

	if d.tun != nil {
		fmt.Printf("  TUN Interface: %s\n", d.tun.Name())
	}

	peers := d.peerManager.GetAllPeers()
	fmt.Printf("  Peers: %d\n", len(peers))
	for _, p := range peers {
		state := "disconnected"
		if p.State == mesh.PeerStateConnected {
			state = "connected"
		} else if p.State == mesh.PeerStateConnecting {
			state = "connecting"
		}
		fmt.Printf("    - %s (%s): %s\n", p.Name, p.VirtualIP, state)
	}
}

func RunDaemon() error {
	cfg, err := config.Load()
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
