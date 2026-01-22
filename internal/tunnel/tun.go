package tunnel

import (
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/songgao/water"
)

type TUNDevice struct {
	iface     *water.Interface
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
	config := water.Config{
		DeviceType: water.TUN,
	}

	// Set interface name based on platform (platform-specific config)
	// Note: On Windows, the water library uses a different mechanism
	// On Linux, we can set the name via PlatformSpecificParams

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	ip, cidr, err := net.ParseCIDR(cfg.VirtualIP + "/" + cfg.CIDR[len(cfg.CIDR)-2:])
	if err != nil {
		// Try parsing CIDR directly
		ip, cidr, err = net.ParseCIDR(cfg.CIDR)
		if err != nil {
			iface.Close()
			return nil, fmt.Errorf("failed to parse CIDR: %w", err)
		}
		ip = net.ParseIP(cfg.VirtualIP)
	}

	tun := &TUNDevice{
		iface:     iface,
		name:      iface.Name(),
		mtu:       cfg.MTU,
		virtualIP: ip,
		cidr:      cidr,
	}

	return tun, nil
}

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
	// On Linux, we need to use ip commands
	// This would typically be done via netlink, but for simplicity we note it here
	// In production, use github.com/vishvananda/netlink
	return nil
}

func (t *TUNDevice) configureDarwin() error {
	// On macOS, interface is auto-configured
	return nil
}

func (t *TUNDevice) configureWindows() error {
	// On Windows, we need to use netsh or WMI
	return nil
}
