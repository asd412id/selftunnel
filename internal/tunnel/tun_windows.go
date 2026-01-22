//go:build windows
// +build windows

package tunnel

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/selftunnel/selftunnel/internal/tunnel/wintun"
	wintunlib "golang.zx2c4.com/wintun"
)

// WindowsTUN wraps wintun adapter for Windows
type WindowsTUN struct {
	adapter *wintunlib.Adapter
	session wintunlib.Session
	name    string
}

// createPlatformTUN creates a WinTUN interface on Windows
func createPlatformTUN(cfg TUNConfig) (TUNInterface, error) {
	// Ensure wintun.dll is available before creating TUN
	if err := ensureWintunDLL(); err != nil {
		log.Printf("Warning: Could not ensure wintun.dll: %v", err)
	}

	name := cfg.Name
	if name == "" {
		name = "SelfTunnel"
	}

	// Try to open existing adapter first
	adapter, err := wintunlib.OpenAdapter(name)
	if err != nil {
		// Create new adapter
		adapter, err = wintunlib.CreateAdapter(name, "SelfTunnel", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create WinTUN adapter: %w", err)
		}
		log.Printf("Created new WinTUN adapter: %s", name)
	} else {
		log.Printf("Opened existing WinTUN adapter: %s", name)
	}

	// Start session with ring capacity (must be power of 2, between 0x20000 and 0x4000000)
	// Using 0x800000 (8MB) for good performance
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("failed to start WinTUN session: %w", err)
	}

	return &WindowsTUN{
		adapter: adapter,
		session: session,
		name:    name,
	}, nil
}

func (w *WindowsTUN) Read(buf []byte) (int, error) {
	packet, err := w.session.ReceivePacket()
	if err != nil {
		return 0, err
	}
	n := copy(buf, packet)
	w.session.ReleaseReceivePacket(packet)
	return n, nil
}

func (w *WindowsTUN) Write(buf []byte) (int, error) {
	packet, err := w.session.AllocateSendPacket(len(buf))
	if err != nil {
		return 0, err
	}
	copy(packet, buf)
	w.session.SendPacket(packet)
	return len(buf), nil
}

func (w *WindowsTUN) Close() error {
	// Cleanup DNS NRPT rules
	cleanupWindowsDNS()

	w.session.End()
	return w.adapter.Close()
}

func (w *WindowsTUN) Name() string {
	return w.name
}

// ensureWintunDLL extracts wintun.dll to executable directory if needed
func ensureWintunDLL() error {
	// Get executable directory
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	dllPath := filepath.Join(exeDir, "wintun.dll")

	// Check if DLL already exists
	if _, err := os.Stat(dllPath); err == nil {
		log.Printf("wintun.dll found at %s", dllPath)
		return nil
	}

	// Try to extract from embedded wintun package
	if err := wintun.EnsureWinTUN(); err != nil {
		return fmt.Errorf("failed to ensure wintun: %w", err)
	}

	log.Printf("wintun.dll extracted successfully")
	return nil
}

// configureWindowsInterface configures the network interface using netsh
func configureWindowsInterface(name, ip string, cidr *net.IPNet, mtu int) error {
	// Calculate subnet mask from CIDR
	mask := cidr.Mask
	subnetMask := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

	// Set IP address using netsh
	// netsh interface ip set address "SelfTunnel" static 10.99.0.2 255.255.255.0
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		name, "static", ip, subnetMask)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("netsh set address output: %s", string(output))
		return fmt.Errorf("failed to set IP address: %w", err)
	}
	log.Printf("Set IP address %s/%s on interface %s", ip, subnetMask, name)

	// Set DNS server to use our own DNS on the VPN IP
	cmd = exec.Command("netsh", "interface", "ip", "set", "dns",
		name, "static", ip)
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("netsh set dns output: %s", string(output))
		log.Printf("Warning: failed to set DNS server: %v", err)
	} else {
		log.Printf("Set DNS server %s on interface %s", ip, name)
	}

	// Add NRPT rule for .selftunnel domain using PowerShell
	// This tells Windows to use our DNS server for *.selftunnel queries
	psCmd := fmt.Sprintf(`Add-DnsClientNrptRule -Namespace ".selftunnel" -NameServers "%s" -ErrorAction SilentlyContinue`, ip)
	cmd = exec.Command("powershell", "-Command", psCmd)
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("PowerShell NRPT output: %s", string(output))
		log.Printf("Warning: failed to add NRPT rule: %v (DNS may not work for .selftunnel)", err)
	} else {
		log.Printf("Added NRPT rule for .selftunnel -> %s", ip)
	}

	// Set MTU using netsh
	if mtu > 0 {
		cmd = exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
			name, fmt.Sprintf("mtu=%d", mtu), "store=persistent")
		output, err = cmd.CombinedOutput()
		if err != nil {
			log.Printf("netsh set mtu output: %s", string(output))
			// MTU setting may fail, but we can continue
			log.Printf("Warning: failed to set MTU: %v", err)
		} else {
			log.Printf("Set MTU %d on interface %s", mtu, name)
		}
	}

	return nil
}

// cleanupWindowsDNS removes NRPT rules when shutting down
func cleanupWindowsDNS() {
	psCmd := `Get-DnsClientNrptRule | Where-Object {$_.Namespace -eq ".selftunnel"} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue`
	cmd := exec.Command("powershell", "-Command", psCmd)
	cmd.Run() // Ignore errors during cleanup
}
