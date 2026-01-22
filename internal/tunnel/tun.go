package tunnel

import (
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// TUNInterface is the common interface for TUN device implementations
type TUNInterface interface {
	io.ReadWriteCloser
	Name() string
}

type TUNDevice struct {
	iface     TUNInterface
	name      string
	mtu       int
	virtualIP net.IP
	cidr      *net.IPNet
	mu        sync.RWMutex
	running   bool
}

type TUNConfig struct {
	Name      string
	MTU       int
	VirtualIP string
	CIDR      string
}

func NewTUN(cfg TUNConfig) (*TUNDevice, error) {
	// Parse IP and CIDR first
	ip, cidr, err := net.ParseCIDR(cfg.VirtualIP + "/" + cfg.CIDR[len(cfg.CIDR)-2:])
	if err != nil {
		// Try parsing CIDR directly
		ip, cidr, err = net.ParseCIDR(cfg.CIDR)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR: %w", err)
		}
		ip = net.ParseIP(cfg.VirtualIP)
	}

	// Create platform-specific TUN interface
	iface, err := createPlatformTUN(cfg)
	if err != nil {
		return nil, err
	}

	tun := &TUNDevice{
		iface:     iface,
		name:      iface.Name(),
		mtu:       cfg.MTU,
		virtualIP: ip,
		cidr:      cidr,
		running:   true,
	}

	return tun, nil
}

// createPlatformTUN is implemented in platform-specific files:
// - tun_windows.go for Windows (uses WinTUN)
// - tun_unix.go for Linux/macOS (uses water/TAP)

// Name returns the interface name
func (t *TUNDevice) Name() string {
	return t.name
}

// Read reads a packet from the TUN device
func (t *TUNDevice) Read(buf []byte) (int, error) {
	return t.iface.Read(buf)
}

// Write writes a packet to the TUN device
func (t *TUNDevice) Write(buf []byte) (int, error) {
	return t.iface.Write(buf)
}

// Close closes the TUN device
func (t *TUNDevice) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.running = false
	return t.iface.Close()
}

// VirtualIP returns the virtual IP address
func (t *TUNDevice) VirtualIP() net.IP {
	return t.virtualIP
}

// CIDR returns the network CIDR
func (t *TUNDevice) CIDR() *net.IPNet {
	return t.cidr
}

// MTU returns the MTU
func (t *TUNDevice) MTU() int {
	return t.mtu
}

// ConfigureInterface configures the network interface (platform-specific)
func (t *TUNDevice) ConfigureInterface() error {
	switch runtime.GOOS {
	case "linux":
		return t.configureLinux()
	case "darwin":
		return t.configureDarwin()
	case "windows":
		return t.configureWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func (t *TUNDevice) configureLinux() error {
	// On Linux, we need to use ip commands to configure the interface
	name := t.name
	ip := t.virtualIP.String()
	cidrSize, _ := t.cidr.Mask.Size()
	cidrStr := fmt.Sprintf("%s/%d", ip, cidrSize)

	// Set IP address: ip addr add 10.99.0.2/24 dev tun0
	cmd := exec.Command("ip", "addr", "add", cidrStr, "dev", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Ignore "File exists" error (address already set)
		if !strings.Contains(string(output), "File exists") {
			log.Printf("ip addr add output: %s", string(output))
			return fmt.Errorf("failed to set IP address: %w", err)
		}
	}

	// Bring interface up: ip link set tun0 up
	cmd = exec.Command("ip", "link", "set", name, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("ip link set output: %s", string(output))
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Set MTU if specified
	if t.mtu > 0 {
		cmd = exec.Command("ip", "link", "set", name, "mtu", fmt.Sprintf("%d", t.mtu))
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("ip link set mtu output: %s", string(output))
			// MTU setting may fail, but we can continue
			log.Printf("Warning: failed to set MTU: %v", err)
		}
	}

	log.Printf("Configured Linux TUN interface %s with IP %s", name, cidrStr)
	return nil
}

func (t *TUNDevice) configureDarwin() error {
	// On macOS, interface is auto-configured
	return nil
}

func (t *TUNDevice) configureWindows() error {
	// On Windows, we need to use netsh to configure the interface
	// This is handled in tun_windows.go
	return configureWindowsInterface(t.name, t.virtualIP.String(), t.cidr, t.mtu)
}
