package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/selftunnel/selftunnel/internal/config"
	"github.com/selftunnel/selftunnel/internal/crypto"
	"github.com/selftunnel/selftunnel/internal/mesh"
	"github.com/selftunnel/selftunnel/internal/nat"
	"github.com/selftunnel/selftunnel/internal/signaling"
	"github.com/spf13/cobra"
)

const (
	defaultServiceName = "selftunnel"
	serviceDescription = "SelfTunnel P2P Mesh VPN"
)

func serviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage SelfTunnel system service",
		Long: `Manage SelfTunnel as a system service.

Examples:
  selftunnel service install              - Install with default name
  selftunnel service install --name vpn1  - Install as 'selftunnel-vpn1'
  selftunnel service uninstall            - Remove the service
  selftunnel service start                - Start the service
  selftunnel service stop                 - Stop the service
  selftunnel service restart              - Restart the service
  selftunnel service status               - Show service status
  selftunnel service logs                 - Show service logs`,
	}

	cmd.AddCommand(
		serviceInstallCmd(),
		serviceUninstallCmd(),
		serviceStartCmd(),
		serviceStopCmd(),
		serviceRestartCmd(),
		serviceStatusCmd(),
		serviceLogsCmd(),
	)

	return cmd
}

func getServiceName(name string) string {
	if name == "" {
		return defaultServiceName
	}
	return fmt.Sprintf("%s-%s", defaultServiceName, name)
}

func serviceInstallCmd() *cobra.Command {
	var (
		name          string
		networkID     string
		networkSecret string
		nodeName      string
		signalingURL  string
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install SelfTunnel as a system service",
		Long: `Install SelfTunnel as a system service.

You can setup and install in one command:
  sudo selftunnel service install --network <ID> --secret <SECRET> --node-name <NAME>

Or use --name to create multiple instances:
  sudo selftunnel service install --name office --network <ID> --secret <SECRET> --node-name office-pc

This creates services named 'selftunnel-office' and 'selftunnel-home'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			svcName := getServiceName(name)
			instanceName := name

			// If network credentials provided, setup config first
			if networkID != "" && networkSecret != "" && nodeName != "" {
				fmt.Println("Setting up network configuration...")
				if err := setupNetworkConfig(instanceName, networkID, networkSecret, nodeName, signalingURL); err != nil {
					return fmt.Errorf("failed to setup network: %w", err)
				}
				fmt.Println()
			}

			if runtime.GOOS == "windows" {
				return installWindowsService(svcName, instanceName)
			}
			return installLinuxService(svcName, instanceName)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Service instance name (creates 'selftunnel-<name>')")
	cmd.Flags().StringVar(&networkID, "network", "", "Network ID to join")
	cmd.Flags().StringVar(&networkSecret, "secret", "", "Network secret")
	cmd.Flags().StringVar(&nodeName, "node-name", "", "Name for this node")
	cmd.Flags().StringVar(&signalingURL, "signaling", "", "Signaling server URL (optional)")

	return cmd
}

// setupNetworkConfig creates config and registers with signaling server
func setupNetworkConfig(instanceName, networkID, networkSecret, nodeName, signalingURL string) error {
	cfg := config.DefaultConfig()

	// Generate new key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}

	cfg.NodeName = nodeName
	cfg.PrivateKey = crypto.ToBase64(keyPair.PrivateKey)
	cfg.PublicKey = crypto.ToBase64(keyPair.PublicKey)
	cfg.NetworkID = networkID
	cfg.NetworkSecret = networkSecret
	if signalingURL != "" {
		cfg.SignalingURL = signalingURL
	}

	// Try to create hole puncher for NAT traversal (non-fatal if fails)
	var endpoints []string
	hp, err := nat.NewHolePuncher(cfg.STUNServers) // Use random port to avoid conflicts
	if err != nil {
		fmt.Printf("Warning: Could not create hole puncher: %v\n", err)
		fmt.Println("Continuing without NAT discovery (will be done when service starts)...")
	} else {
		defer hp.Close()

		// Discover public address
		mapped, err := hp.DiscoverPublicAddr()
		if err != nil {
			fmt.Printf("Warning: Could not discover public address: %v\n", err)
		} else {
			fmt.Printf("Public endpoint: %s:%d\n", mapped.IP, mapped.Port)
		}
		endpoints = hp.GetEndpoints()
	}

	// Create local peer
	localPeer := &mesh.Peer{
		Name:      cfg.NodeName,
		PublicKey: cfg.PublicKey,
		Endpoints: endpoints,
	}

	// Connect to signaling server
	fmt.Printf("Connecting to signaling server: %s\n", cfg.SignalingURL)
	client := signaling.NewClient(cfg.SignalingURL, cfg.NetworkID, cfg.NetworkSecret)
	client.SetLocalPeer(localPeer)

	// Register with signaling server
	resp, err := client.Register()
	if err != nil {
		return fmt.Errorf("failed to register with network: %w\n\nPlease check:\n  1. Network ID and Secret are correct\n  2. Signaling server is accessible: %s\n  3. No firewall/proxy blocking the connection", cfg.SignalingURL)
	}

	cfg.VirtualIP = resp.VirtualIP
	fmt.Printf("Registered with network. Virtual IP: %s\n", cfg.VirtualIP)

	// Save config
	if err := cfg.SaveForInstance(instanceName); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	configPath, _ := config.ConfigPathForInstance(instanceName)
	fmt.Printf("Config saved to: %s\n", configPath)

	return nil
}

func serviceUninstallCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall SelfTunnel system service",
		RunE: func(cmd *cobra.Command, args []string) error {
			svcName := getServiceName(name)
			if runtime.GOOS == "windows" {
				return uninstallWindowsService(svcName)
			}
			return uninstallLinuxService(svcName)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Service instance name")

	return cmd
}

func serviceStartCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the SelfTunnel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			svcName := getServiceName(name)
			if runtime.GOOS == "windows" {
				return runCommand("sc", "start", svcName)
			}
			return runCommand("systemctl", "start", svcName)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Service instance name")

	return cmd
}

func serviceStopCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the SelfTunnel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			svcName := getServiceName(name)
			if runtime.GOOS == "windows" {
				return runCommand("sc", "stop", svcName)
			}
			return runCommand("systemctl", "stop", svcName)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Service instance name")

	return cmd
}

func serviceRestartCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart the SelfTunnel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			svcName := getServiceName(name)
			if runtime.GOOS == "windows" {
				runCommand("sc", "stop", svcName)
				return runCommand("sc", "start", svcName)
			}
			return runCommand("systemctl", "restart", svcName)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Service instance name")

	return cmd
}

func serviceStatusCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show SelfTunnel service status",
		RunE: func(cmd *cobra.Command, args []string) error {
			svcName := getServiceName(name)
			if runtime.GOOS == "windows" {
				return runCommand("sc", "query", svcName)
			}
			return runCommand("systemctl", "status", svcName, "--no-pager")
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Service instance name")

	return cmd
}

func serviceLogsCmd() *cobra.Command {
	var (
		name   string
		follow bool
		lines  int
	)

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show SelfTunnel service logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			svcName := getServiceName(name)
			if runtime.GOOS == "windows" {
				fmt.Println("On Windows, check Event Viewer for service logs")
				return nil
			}

			cmdArgs := []string{"-u", svcName}
			if follow {
				cmdArgs = append(cmdArgs, "-f")
			}
			if lines > 0 {
				cmdArgs = append(cmdArgs, "-n", fmt.Sprintf("%d", lines))
			}
			return runCommand("journalctl", cmdArgs...)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Service instance name")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "Number of lines to show")

	return cmd
}

func installLinuxService(svcName, instanceName string) error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root (use sudo)")
	}

	// Check if config exists
	configPath, err := config.ConfigPathForInstance(instanceName)
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config not found at %s. Run 'selftunnel join' first or provide --network, --secret, --node-name flags", configPath)
	}

	// Get the path to the current executable
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	execPath, err = filepath.Abs(execPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Determine target binary path
	targetPath := fmt.Sprintf("/usr/local/bin/%s", svcName)

	// Copy binary if not already there
	if execPath != targetPath {
		fmt.Printf("Copying %s to %s...\n", execPath, targetPath)
		input, err := os.ReadFile(execPath)
		if err != nil {
			return fmt.Errorf("failed to read binary: %w", err)
		}
		if err := os.WriteFile(targetPath, input, 0755); err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	// Build ExecStart command with instance name if needed
	execStart := fmt.Sprintf("%s up", targetPath)
	if instanceName != "" {
		execStart = fmt.Sprintf("%s up --instance %s", targetPath, instanceName)
	}

	// Create systemd service file
	serviceContent := fmt.Sprintf(`[Unit]
Description=%s
Documentation=https://github.com/asd412id/selftunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s
Restart=always
RestartSec=5
LimitNOFILE=65535

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=%s

# Security
NoNewPrivileges=no
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
`, serviceDescription, execStart, svcName)

	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", svcName)
	fmt.Printf("Creating service file at %s...\n", servicePath)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}

	// Reload systemd
	fmt.Println("Reloading systemd...")
	if err := runCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}

	// Enable service
	fmt.Println("Enabling service...")
	if err := runCommand("systemctl", "enable", svcName); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("✓ SelfTunnel service '%s' installed successfully!\n", svcName)
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Printf("  selftunnel service start --name %s    - Start the service\n", getInstanceName(svcName))
	fmt.Printf("  selftunnel service stop --name %s     - Stop the service\n", getInstanceName(svcName))
	fmt.Printf("  selftunnel service status --name %s   - Check service status\n", getInstanceName(svcName))
	fmt.Printf("  selftunnel service logs --name %s -f  - Follow service logs\n", getInstanceName(svcName))
	fmt.Println()
	fmt.Println("Or use systemctl directly:")
	fmt.Printf("  sudo systemctl start %s\n", svcName)
	fmt.Printf("  sudo systemctl status %s\n", svcName)
	fmt.Printf("  sudo journalctl -u %s -f\n", svcName)

	return nil
}

func uninstallLinuxService(svcName string) error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root (use sudo)")
	}

	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", svcName)

	// Check if service exists
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		fmt.Printf("Service '%s' is not installed.\n", svcName)
		return nil
	}

	// Stop service if running
	fmt.Println("Stopping service...")
	runCommand("systemctl", "stop", svcName)

	// Disable service
	fmt.Println("Disabling service...")
	runCommand("systemctl", "disable", svcName)

	// Remove service file
	fmt.Printf("Removing %s...\n", servicePath)
	if err := os.Remove(servicePath); err != nil {
		return fmt.Errorf("failed to remove service file: %w", err)
	}

	// Reload systemd
	fmt.Println("Reloading systemd...")
	if err := runCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("✓ SelfTunnel service '%s' uninstalled successfully!\n", svcName)
	fmt.Println()
	targetPath := fmt.Sprintf("/usr/local/bin/%s", svcName)
	fmt.Printf("Note: The binary at %s was not removed.\n", targetPath)
	fmt.Printf("      To remove it, run: sudo rm %s\n", targetPath)

	return nil
}

func installWindowsService(svcName, instanceName string) error {
	// Check if config exists
	configPath, err := config.ConfigPathForInstance(instanceName)
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config not found at %s. Run 'selftunnel join' first or provide --network, --secret, --node-name flags", configPath)
	}

	// Get the path to the current executable
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	execPath, err = filepath.Abs(execPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Create the service using sc.exe
	fmt.Printf("Creating Windows service '%s'...\n", svcName)

	// Build binPath with instance name if needed
	binPath := fmt.Sprintf("\"%s\" up", execPath)
	if instanceName != "" {
		binPath = fmt.Sprintf("\"%s\" up --instance %s", execPath, instanceName)
	}

	displayName := serviceDescription
	if svcName != defaultServiceName {
		displayName = fmt.Sprintf("%s (%s)", serviceDescription, svcName)
	}

	cmd := exec.Command("sc", "create", svcName,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", displayName)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "1073") {
			fmt.Printf("Service '%s' already exists. To reinstall, run 'selftunnel service uninstall --name %s' first.\n", svcName, getInstanceName(svcName))
			return nil
		}
		return fmt.Errorf("failed to create service: %s", string(output))
	}

	// Set description
	exec.Command("sc", "description", svcName, serviceDescription).Run()

	// Configure failure recovery
	exec.Command("sc", "failure", svcName, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000").Run()

	fmt.Println()
	fmt.Printf("✓ SelfTunnel service '%s' installed successfully!\n", svcName)
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Printf("  selftunnel service start --name %s   - Start the service\n", getInstanceName(svcName))
	fmt.Printf("  selftunnel service stop --name %s    - Stop the service\n", getInstanceName(svcName))
	fmt.Printf("  selftunnel service status --name %s  - Check service status\n", getInstanceName(svcName))
	fmt.Println()
	fmt.Println("Or use Windows Services (services.msc) to manage the service.")

	return nil
}

func uninstallWindowsService(svcName string) error {
	// Stop service first
	fmt.Println("Stopping service...")
	exec.Command("sc", "stop", svcName).Run()

	// Delete service
	fmt.Println("Removing service...")
	cmd := exec.Command("sc", "delete", svcName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "1060") {
			fmt.Printf("Service '%s' does not exist.\n", svcName)
			return nil
		}
		return fmt.Errorf("failed to delete service: %s", string(output))
	}

	fmt.Println()
	fmt.Printf("✓ SelfTunnel service '%s' uninstalled successfully!\n", svcName)

	return nil
}

// getInstanceName returns the instance name from full service name
func getInstanceName(svcName string) string {
	if svcName == defaultServiceName {
		return ""
	}
	return strings.TrimPrefix(svcName, defaultServiceName+"-")
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
