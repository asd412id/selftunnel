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
	"strings"

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
	// Cleanup DNS NRPT rules and hosts file entries
	cleanupWindowsDNS()

	w.session.End()
	return w.adapter.Close()
}

func (w *WindowsTUN) Name() string {
	return w.name
}

// ensureWintunDLL extracts wintun.dll to executable directory if needed
// IMPORTANT: The golang.zx2c4.com/wintun library uses LoadLibraryEx with
// LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
// This means it ONLY searches the application directory and System32.
// It does NOT search PATH, temp directory, or current working directory.
func ensureWintunDLL() error {
	// Get executable directory - this is where wintun library will search
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	dllPath := filepath.Join(exeDir, "wintun.dll")

	// Check if DLL already exists in exe directory
	if _, err := os.Stat(dllPath); err == nil {
		log.Printf("wintun.dll found at %s", dllPath)
		return nil
	}

	// Also check System32 as fallback
	systemPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "wintun.dll")
	if _, err := os.Stat(systemPath); err == nil {
		log.Printf("wintun.dll found at %s", systemPath)
		return nil
	}

	// Extract embedded DLL directly to exe directory
	log.Printf("Extracting wintun.dll to %s", dllPath)
	if err := wintun.ExtractToPath(dllPath); err != nil {
		// Try System32 as fallback (requires admin)
		log.Printf("Failed to extract to exe directory: %v, trying System32...", err)
		if err2 := wintun.InstallWinTUN(); err2 != nil {
			return fmt.Errorf("failed to extract wintun.dll: exe dir error: %v, system32 error: %w", err, err2)
		}
		log.Printf("wintun.dll installed to System32")
		return nil
	}

	log.Printf("wintun.dll extracted successfully to %s", dllPath)
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
	// First remove any existing rule to avoid duplicates
	psCleanup := `Get-DnsClientNrptRule | Where-Object {$_.Namespace -eq ".selftunnel"} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue`
	cmd = exec.Command("powershell", "-Command", psCleanup)
	cmd.Run() // Ignore errors

	psCmd := fmt.Sprintf(`Add-DnsClientNrptRule -Namespace ".selftunnel" -NameServers "%s" -ErrorAction Stop`, ip)
	cmd = exec.Command("powershell", "-Command", psCmd)
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("PowerShell NRPT output: %s", string(output))
		log.Printf("Warning: failed to add NRPT rule: %v (DNS may not work for .selftunnel)", err)
	} else {
		log.Printf("Added NRPT rule for .selftunnel -> %s", ip)
	}

	// Verify NRPT rule was added
	psVerify := `Get-DnsClientNrptRule | Where-Object {$_.Namespace -eq ".selftunnel"} | Format-List Namespace,NameServers`
	cmd = exec.Command("powershell", "-Command", psVerify)
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to verify NRPT rule: %v", err)
	} else {
		log.Printf("NRPT rule verification:\n%s", string(output))
	}

	// Flush DNS cache to ensure new rules take effect immediately
	cmd = exec.Command("ipconfig", "/flushdns")
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("ipconfig /flushdns output: %s", string(output))
	} else {
		log.Printf("Flushed DNS cache")
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

// cleanupWindowsDNS removes NRPT rules and hosts file entries when shutting down
func cleanupWindowsDNS() {
	psCmd := `Get-DnsClientNrptRule | Where-Object {$_.Namespace -eq ".selftunnel"} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue`
	cmd := exec.Command("powershell", "-Command", psCmd)
	cmd.Run() // Ignore errors during cleanup

	// Clean up hosts file entries
	cleanupHostsFile()
}

// hostsFilePath returns the path to Windows hosts file
func hostsFilePath() string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
}

// addHostsEntry adds an entry to the Windows hosts file for DNS resolution fallback
func addHostsEntry(ip, hostname string) error {
	hostsPath := hostsFilePath()

	// Read existing content
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	// Check if entry already exists
	entry := fmt.Sprintf("%s\t%s", ip, hostname)
	if strings.Contains(string(content), entry) {
		return nil // Already exists
	}

	// Check if hostname exists with different IP (update it)
	lines := strings.Split(string(content), "\n")
	updated := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, "\t"+hostname) || strings.HasSuffix(trimmed, " "+hostname) {
			lines[i] = entry
			updated = true
			break
		}
	}

	var newContent string
	if updated {
		newContent = strings.Join(lines, "\n")
	} else {
		// Append new entry with selftunnel marker
		marker := "# SelfTunnel DNS entry"
		if !strings.Contains(string(content), marker) {
			newContent = string(content) + "\n\n" + marker + "\n"
		} else {
			newContent = string(content) + "\n"
		}
		newContent += entry
	}

	// Write back
	if err := os.WriteFile(hostsPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write hosts file: %w", err)
	}

	log.Printf("Added hosts entry: %s -> %s", hostname, ip)
	return nil
}

// cleanupHostsFile removes SelfTunnel entries from hosts file
func cleanupHostsFile() {
	hostsPath := hostsFilePath()

	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	inSelfTunnelSection := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect start of SelfTunnel section
		if strings.Contains(trimmed, "# SelfTunnel DNS entry") {
			inSelfTunnelSection = true
			continue
		}

		// Skip .selftunnel entries
		if strings.Contains(trimmed, ".selftunnel") {
			continue
		}

		// End SelfTunnel section on next comment or empty line after entries
		if inSelfTunnelSection && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			inSelfTunnelSection = false
		}

		if !inSelfTunnelSection {
			newLines = append(newLines, line)
		}
	}

	os.WriteFile(hostsPath, []byte(strings.Join(newLines, "\n")), 0644)
}

// UpdateHostsForPeer adds a hosts file entry for a peer (call this when peers are discovered)
func UpdateHostsForPeer(name, virtualIP, suffix string) {
	if suffix == "" {
		suffix = "selftunnel"
	}
	hostname := fmt.Sprintf("%s.%s", name, suffix)
	if err := addHostsEntry(virtualIP, hostname); err != nil {
		log.Printf("Warning: Could not add hosts entry for %s: %v", name, err)
	}
}
