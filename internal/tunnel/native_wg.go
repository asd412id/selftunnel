package tunnel

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// NativeWG wraps the official wireguard-go implementation
type NativeWG struct {
	device     *device.Device
	tunDevice  tun.Device
	tunName    string
	privateKey string
	publicKey  string
	listenPort int
	address    string // Virtual IP with CIDR
	mtu        int
	peers      map[string]*NativeWGPeer
	peersMu    sync.RWMutex
	started    bool
}

type NativeWGPeer struct {
	PublicKey           string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
	LastHandshake       time.Time
	TxBytes             uint64
	RxBytes             uint64
}

type NativeWGConfig struct {
	PrivateKey string // base64 encoded
	Address    string // e.g., "10.99.0.1/24"
	ListenPort int
	MTU        int
}

// NewNativeWG creates a new native WireGuard tunnel
func NewNativeWG(cfg NativeWGConfig) (*NativeWG, error) {
	// Decode and re-encode to get public key
	privKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes")
	}

	// Derive public key
	pubKeyBytes := derivePublicKey(privKeyBytes)
	publicKey := base64.StdEncoding.EncodeToString(pubKeyBytes)

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1420
	}

	return &NativeWG{
		privateKey: cfg.PrivateKey,
		publicKey:  publicKey,
		listenPort: cfg.ListenPort,
		address:    cfg.Address,
		mtu:        mtu,
		peers:      make(map[string]*NativeWGPeer),
	}, nil
}

// Start initializes and starts the WireGuard tunnel
func (n *NativeWG) Start() error {
	if n.started {
		return fmt.Errorf("already started")
	}

	tunName := "selftunnel0"
	if runtime.GOOS == "windows" {
		tunName = "SelfTunnel"
	}

	// Create TUN device
	tunDev, err := tun.CreateTUN(tunName, n.mtu)
	if err != nil {
		return fmt.Errorf("failed to create TUN: %w", err)
	}
	n.tunDevice = tunDev

	// Get actual TUN name
	name, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return fmt.Errorf("failed to get TUN name: %w", err)
	}
	n.tunName = name

	// Create logger (less verbose in production)
	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("[WG %s] ", name))

	// Create WireGuard device
	n.device = device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	// Configure private key and listen port
	ipcConfig := fmt.Sprintf("private_key=%s\nlisten_port=%d\n",
		keyToHex(n.privateKey), n.listenPort)

	if err := n.device.IpcSet(ipcConfig); err != nil {
		n.device.Close()
		return fmt.Errorf("failed to set config: %w", err)
	}

	// Bring device up
	if err := n.device.Up(); err != nil {
		n.device.Close()
		return fmt.Errorf("failed to bring up device: %w", err)
	}

	// Configure IP address on the interface
	if err := n.configureInterface(); err != nil {
		log.Printf("[NativeWG] Warning: failed to configure interface: %v", err)
	}

	n.started = true
	log.Printf("[NativeWG] Started on interface %s, listening on port %d", n.tunName, n.listenPort)
	log.Printf("[NativeWG] Public key: %s", n.publicKey)

	return nil
}

// AddPeer adds a peer to the WireGuard device
func (n *NativeWG) AddPeer(publicKey, endpoint string, allowedIPs []string) error {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()

	peer := &NativeWGPeer{
		PublicKey:           publicKey,
		Endpoint:            endpoint,
		AllowedIPs:          allowedIPs,
		PersistentKeepalive: 25,
	}
	n.peers[publicKey] = peer

	// Build IPC config
	config := fmt.Sprintf("public_key=%s\n", keyToHex(publicKey))

	if endpoint != "" {
		config += fmt.Sprintf("endpoint=%s\n", endpoint)
	}

	for _, ip := range allowedIPs {
		config += fmt.Sprintf("allowed_ip=%s\n", ip)
	}

	config += "persistent_keepalive_interval=25\n"

	if err := n.device.IpcSet(config); err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}

	epStr := endpoint
	if epStr == "" {
		epStr = "(none)"
	}
	log.Printf("[NativeWG] Added peer %s... endpoint=%s allowed=%v", publicKey[:16], epStr, allowedIPs)
	return nil
}

// UpdatePeerEndpoint updates a peer's endpoint for hole punching
func (n *NativeWG) UpdatePeerEndpoint(publicKey, endpoint string) error {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()

	if peer, ok := n.peers[publicKey]; ok {
		peer.Endpoint = endpoint
	}

	config := fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n",
		keyToHex(publicKey), endpoint)

	if err := n.device.IpcSet(config); err != nil {
		return fmt.Errorf("failed to update endpoint: %w", err)
	}

	log.Printf("[NativeWG] Updated peer %s... endpoint to %s", publicKey[:16], endpoint)
	return nil
}

// RemovePeer removes a peer
func (n *NativeWG) RemovePeer(publicKey string) error {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()

	config := fmt.Sprintf("public_key=%s\nremove=true\n", keyToHex(publicKey))

	if err := n.device.IpcSet(config); err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}

	delete(n.peers, publicKey)
	log.Printf("[NativeWG] Removed peer %s...", publicKey[:16])
	return nil
}

// GetPeerStats returns stats for a peer
func (n *NativeWG) GetPeerStats(publicKey string) (rxBytes, txBytes uint64, lastHandshake time.Time) {
	stats, err := n.device.IpcGet()
	if err != nil {
		return
	}

	hexKey := keyToHex(publicKey)
	lines := strings.Split(stats, "\n")
	inPeer := false

	for _, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			inPeer = strings.TrimPrefix(line, "public_key=") == hexKey
		}
		if !inPeer {
			continue
		}
		if strings.HasPrefix(line, "rx_bytes=") {
			fmt.Sscanf(line, "rx_bytes=%d", &rxBytes)
		}
		if strings.HasPrefix(line, "tx_bytes=") {
			fmt.Sscanf(line, "tx_bytes=%d", &txBytes)
		}
		if strings.HasPrefix(line, "last_handshake_time_sec=") {
			var sec int64
			fmt.Sscanf(line, "last_handshake_time_sec=%d", &sec)
			if sec > 0 {
				lastHandshake = time.Unix(sec, 0)
			}
		}
	}
	return
}

// Stop stops the WireGuard device
func (n *NativeWG) Stop() {
	if n.device != nil {
		n.device.Close()
	}
	n.started = false
	log.Printf("[NativeWG] Stopped")
}

// PublicKey returns the public key
func (n *NativeWG) PublicKey() string {
	return n.publicKey
}

// TunName returns the TUN interface name
func (n *NativeWG) TunName() string {
	return n.tunName
}

// configureInterface sets up IP address on the TUN interface
func (n *NativeWG) configureInterface() error {
	// Extract IP and mask from address
	ip, ipNet, err := net.ParseCIDR(n.address)
	if err != nil {
		return fmt.Errorf("invalid address %s: %w", n.address, err)
	}

	switch runtime.GOOS {
	case "windows":
		// Use netsh on Windows
		maskBits, _ := ipNet.Mask.Size()
		cmd := exec.Command("netsh", "interface", "ip", "set", "address",
			n.tunName, "static", ip.String(), fmt.Sprintf("%d.%d.%d.%d",
				ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3]))
		if out, err := cmd.CombinedOutput(); err != nil {
			// Try alternative method
			cmd = exec.Command("netsh", "interface", "ipv4", "set", "address",
				fmt.Sprintf("name=%s", n.tunName), "source=static",
				fmt.Sprintf("addr=%s", ip.String()),
				fmt.Sprintf("mask=%d.%d.%d.%d",
					ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3]))
			if out2, err2 := cmd.CombinedOutput(); err2 != nil {
				return fmt.Errorf("netsh failed: %s / %s", string(out), string(out2))
			}
		}
		_ = maskBits

	case "linux":
		// Use ip command on Linux
		cmd := exec.Command("ip", "addr", "add", n.address, "dev", n.tunName)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip addr add failed: %s", string(out))
		}
		cmd = exec.Command("ip", "link", "set", n.tunName, "up")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip link set up failed: %s", string(out))
		}

	case "darwin":
		// Use ifconfig on macOS
		cmd := exec.Command("ifconfig", n.tunName, "inet", ip.String(), ip.String(), "up")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ifconfig failed: %s", string(out))
		}
	}

	log.Printf("[NativeWG] Configured interface %s with %s", n.tunName, n.address)
	return nil
}

// keyToHex converts base64 key to hex for WireGuard IPC
func keyToHex(base64Key string) string {
	keyBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil || len(keyBytes) != 32 {
		return ""
	}
	return fmt.Sprintf("%x", keyBytes)
}

// derivePublicKey derives public key from private key using curve25519
func derivePublicKey(privateKey []byte) []byte {
	var privateKey32 [32]byte
	copy(privateKey32[:], privateKey)

	// Clamp the private key per WireGuard spec
	privateKey32[0] &= 248
	privateKey32[31] &= 127
	privateKey32[31] |= 64

	publicKey, err := curve25519.X25519(privateKey32[:], curve25519.Basepoint)
	if err != nil {
		log.Printf("[NativeWG] Warning: curve25519 failed: %v", err)
		return make([]byte, 32)
	}

	return publicKey
}
