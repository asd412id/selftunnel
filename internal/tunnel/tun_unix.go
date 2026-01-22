//go:build !windows
// +build !windows

package tunnel

import (
	"fmt"
	"net"

	"github.com/songgao/water"
)

// waterTUN wraps water.Interface to implement TUNInterface
type waterTUN struct {
	iface *water.Interface
}

func (w *waterTUN) Read(buf []byte) (int, error) {
	return w.iface.Read(buf)
}

func (w *waterTUN) Write(buf []byte) (int, error) {
	return w.iface.Write(buf)
}

func (w *waterTUN) Close() error {
	return w.iface.Close()
}

func (w *waterTUN) Name() string {
	return w.iface.Name()
}

// createPlatformTUN creates a TUN interface for Linux/macOS using water
func createPlatformTUN(cfg TUNConfig) (TUNInterface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	return &waterTUN{iface: iface}, nil
}

// configureWindowsInterface stub for non-Windows builds
func configureWindowsInterface(name, ip string, cidr *net.IPNet, mtu int) error {
	return nil // No-op on Unix
}
