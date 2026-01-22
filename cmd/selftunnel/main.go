package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/selftunnel/selftunnel/internal/config"
	"github.com/selftunnel/selftunnel/internal/crypto"
	"github.com/selftunnel/selftunnel/internal/mesh"
	"github.com/selftunnel/selftunnel/internal/nat"
	"github.com/selftunnel/selftunnel/internal/signaling"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
	cfg     *config.Config
)

func main() {
	var err error
	cfg, err = config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	rootCmd := &cobra.Command{
		Use:   "selftunnel",
		Short: "SelfTunnel - P2P mesh VPN tunnel",
		Long: `SelfTunnel is a peer-to-peer mesh VPN that allows you to securely 
connect multiple devices without requiring a central server for traffic relay.`,
		Version: version,
	}

	rootCmd.AddCommand(
		initCmd(),
		joinCmd(),
		leaveCmd(),
		statusCmd(),
		peersCmd(),
		generateCmd(),
		upCmd(),
		serviceCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initCmd() *cobra.Command {
	var networkName string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new SelfTunnel network",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Generate new key pair
			keyPair, err := crypto.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate keys: %w", err)
			}

			// Generate network ID and secret
			networkID, err := crypto.GenerateNetworkID()
			if err != nil {
				return fmt.Errorf("failed to generate network ID: %w", err)
			}

			networkSecret, err := crypto.GenerateNetworkSecret()
			if err != nil {
				return fmt.Errorf("failed to generate network secret: %w", err)
			}

			// Update config
			cfg.NodeName = networkName
			cfg.PrivateKey = crypto.ToBase64(keyPair.PrivateKey)
			cfg.PublicKey = crypto.ToBase64(keyPair.PublicKey)
			cfg.NetworkID = networkID
			cfg.NetworkSecret = networkSecret

			if err := cfg.Save(); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			fmt.Println("Network initialized successfully!")
			fmt.Println()
			fmt.Printf("Network ID:     %s\n", networkID)
			fmt.Printf("Network Secret: %s\n", networkSecret)
			fmt.Printf("Public Key:     %s\n", cfg.PublicKey)
			fmt.Println()
			fmt.Println("Share the Network ID and Secret with other peers to join this network.")
			fmt.Println("Keep the Network Secret safe - anyone with it can join your network!")

			return nil
		},
	}

	cmd.Flags().StringVarP(&networkName, "name", "n", "", "Name for this node")
	cmd.MarkFlagRequired("name")

	return cmd
}

func joinCmd() *cobra.Command {
	var (
		networkID     string
		networkSecret string
		nodeName      string
		signalingURL  string
	)

	cmd := &cobra.Command{
		Use:   "join",
		Short: "Join an existing SelfTunnel network",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use existing keys or generate new ones
			if cfg.PrivateKey == "" {
				keyPair, err := crypto.GenerateKeyPair()
				if err != nil {
					return fmt.Errorf("failed to generate keys: %w", err)
				}
				cfg.PrivateKey = crypto.ToBase64(keyPair.PrivateKey)
				cfg.PublicKey = crypto.ToBase64(keyPair.PublicKey)
			}

			// Update config
			cfg.NodeName = nodeName
			cfg.NetworkID = networkID
			cfg.NetworkSecret = networkSecret
			if signalingURL != "" {
				cfg.SignalingURL = signalingURL
			}

			if err := cfg.Save(); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			fmt.Println("Joining network...")

			// Create hole puncher for NAT traversal
			hp, err := nat.NewHolePuncherWithPort(cfg.STUNServers, cfg.ListenPort)
			if err != nil {
				return fmt.Errorf("failed to create hole puncher: %w", err)
			}
			defer hp.Close()

			// Discover public address
			mapped, err := hp.DiscoverPublicAddr()
			if err != nil {
				fmt.Printf("Warning: Could not discover public address: %v\n", err)
			} else {
				fmt.Printf("Public endpoint: %s:%d\n", mapped.IP, mapped.Port)
			}

			// Create local peer
			localPeer := &mesh.Peer{
				Name:      cfg.NodeName,
				PublicKey: cfg.PublicKey,
				Endpoints: hp.GetEndpoints(),
			}

			// Connect to signaling server
			client := signaling.NewClient(cfg.SignalingURL, cfg.NetworkID, cfg.NetworkSecret)
			client.SetLocalPeer(localPeer)

			// Register with signaling server
			resp, err := client.Register()
			if err != nil {
				return fmt.Errorf("failed to register: %w", err)
			}

			cfg.VirtualIP = resp.VirtualIP
			if err := cfg.Save(); err != nil {
				fmt.Printf("Warning: Could not save virtual IP: %v\n", err)
			}

			fmt.Printf("Joined network successfully!\n")
			fmt.Printf("Virtual IP: %s\n", cfg.VirtualIP)

			// Start background services
			client.Start()
			defer client.Stop()

			// Wait for interrupt
			fmt.Println("\nPress Ctrl+C to leave the network...")
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			<-sigChan

			fmt.Println("\nLeaving network...")
			return nil
		},
	}

	cmd.Flags().StringVar(&networkID, "network", "", "Network ID to join")
	cmd.Flags().StringVar(&networkSecret, "secret", "", "Network secret")
	cmd.Flags().StringVarP(&nodeName, "name", "n", "", "Name for this node")
	cmd.Flags().StringVar(&signalingURL, "signaling", "", "Signaling server URL (optional)")

	cmd.MarkFlagRequired("network")
	cmd.MarkFlagRequired("secret")
	cmd.MarkFlagRequired("name")

	return cmd
}

func leaveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "leave",
		Short: "Leave the current network",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.NetworkID == "" {
				return fmt.Errorf("not currently in a network")
			}

			// Create local peer
			localPeer := &mesh.Peer{
				PublicKey: cfg.PublicKey,
			}

			// Connect to signaling server and unregister
			client := signaling.NewClient(cfg.SignalingURL, cfg.NetworkID, cfg.NetworkSecret)
			client.SetLocalPeer(localPeer)

			if err := client.Unregister(); err != nil {
				fmt.Printf("Warning: Could not unregister from signaling server: %v\n", err)
			}

			// Clear network config
			cfg.NetworkID = ""
			cfg.NetworkSecret = ""
			cfg.VirtualIP = ""

			if err := cfg.Save(); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			fmt.Println("Left network successfully.")
			return nil
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("SelfTunnel Status")
			fmt.Println("=================")
			fmt.Printf("Node Name:    %s\n", cfg.NodeName)
			fmt.Printf("Public Key:   %s\n", cfg.PublicKey)
			fmt.Printf("Network ID:   %s\n", cfg.NetworkID)
			fmt.Printf("Virtual IP:   %s\n", cfg.VirtualIP)
			fmt.Printf("Listen Port:  %d\n", cfg.ListenPort)
			fmt.Printf("Signaling:    %s\n", cfg.SignalingURL)

			if cfg.NetworkID != "" {
				// Get peers from signaling server
				client := signaling.NewClient(cfg.SignalingURL, cfg.NetworkID, cfg.NetworkSecret)
				peers, err := client.GetPeers()
				if err != nil {
					fmt.Printf("\nFailed to get peers: %v\n", err)
				} else {
					fmt.Printf("\nPeers Online: %d\n", len(peers))
				}
			}

			return nil
		},
	}
}

func peersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "peers",
		Short: "List all peers in the network",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.NetworkID == "" {
				return fmt.Errorf("not currently in a network")
			}

			client := signaling.NewClient(cfg.SignalingURL, cfg.NetworkID, cfg.NetworkSecret)
			peers, err := client.GetPeers()
			if err != nil {
				return fmt.Errorf("failed to get peers: %w", err)
			}

			if len(peers) == 0 {
				fmt.Println("No peers found in the network.")
				return nil
			}

			fmt.Printf("%-20s %-15s %-44s %s\n", "NAME", "VIRTUAL IP", "PUBLIC KEY", "ENDPOINTS")
			fmt.Println(string(make([]byte, 100)))

			for _, peer := range peers {
				isSelf := ""
				if peer.PublicKey == cfg.PublicKey {
					isSelf = " (you)"
				}

				endpoints := ""
				if len(peer.Endpoints) > 0 {
					endpoints = peer.Endpoints[0]
					if len(peer.Endpoints) > 1 {
						endpoints += fmt.Sprintf(" (+%d)", len(peer.Endpoints)-1)
					}
				}

				fmt.Printf("%-20s %-15s %-44s %s%s\n",
					peer.Name,
					peer.VirtualIP,
					peer.PublicKey[:44],
					endpoints,
					isSelf,
				)
			}

			return nil
		},
	}
}

func upCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Start the SelfTunnel daemon",
		Long:  "Start the SelfTunnel daemon to establish mesh VPN connections with peers.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunDaemon()
		},
	}
}

func generateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate various keys and identifiers",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "keys",
		Short: "Generate a new key pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			keyPair, err := crypto.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate keys: %w", err)
			}

			fmt.Printf("Private Key: %s\n", crypto.ToBase64(keyPair.PrivateKey))
			fmt.Printf("Public Key:  %s\n", crypto.ToBase64(keyPair.PublicKey))
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "network-secret",
		Short: "Generate a new network secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			secret, err := crypto.GenerateNetworkSecret()
			if err != nil {
				return fmt.Errorf("failed to generate secret: %w", err)
			}
			fmt.Printf("Network Secret: %s\n", secret)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "network-id",
		Short: "Generate a new network ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := crypto.GenerateNetworkID()
			if err != nil {
				return fmt.Errorf("failed to generate ID: %w", err)
			}
			fmt.Printf("Network ID: %s\n", id)
			return nil
		},
	})

	return cmd
}
