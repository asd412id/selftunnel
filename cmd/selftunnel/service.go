package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

const (
	serviceName        = "selftunnel"
	serviceDescription = "SelfTunnel P2P Mesh VPN"
)

func serviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage SelfTunnel system service",
		Long: `Manage SelfTunnel as a system service.

Examples:
  selftunnel service install    - Install and enable the service
  selftunnel service uninstall  - Stop and remove the service
  selftunnel service start      - Start the service
  selftunnel service stop       - Stop the service
  selftunnel service restart    - Restart the service
  selftunnel service status     - Show service status
  selftunnel service logs       - Show service logs`,
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

func serviceInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install SelfTunnel as a system service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "windows" {
				return installWindowsService()
			}
			return installLinuxService()
		},
	}
}

func serviceUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall SelfTunnel system service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "windows" {
				return uninstallWindowsService()
			}
			return uninstallLinuxService()
		},
	}
}

func serviceStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the SelfTunnel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "windows" {
				return runCommand("sc", "start", serviceName)
			}
			return runCommand("systemctl", "start", serviceName)
		},
	}
}

func serviceStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the SelfTunnel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "windows" {
				return runCommand("sc", "stop", serviceName)
			}
			return runCommand("systemctl", "stop", serviceName)
		},
	}
}

func serviceRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Restart the SelfTunnel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "windows" {
				runCommand("sc", "stop", serviceName)
				return runCommand("sc", "start", serviceName)
			}
			return runCommand("systemctl", "restart", serviceName)
		},
	}
}

func serviceStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show SelfTunnel service status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "windows" {
				return runCommand("sc", "query", serviceName)
			}
			return runCommand("systemctl", "status", serviceName, "--no-pager")
		},
	}
}

func serviceLogsCmd() *cobra.Command {
	var follow bool
	var lines int

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show SelfTunnel service logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "windows" {
				fmt.Println("On Windows, check Event Viewer for service logs")
				return nil
			}

			cmdArgs := []string{"-u", serviceName}
			if follow {
				cmdArgs = append(cmdArgs, "-f")
			}
			if lines > 0 {
				cmdArgs = append(cmdArgs, "-n", fmt.Sprintf("%d", lines))
			}
			return runCommand("journalctl", cmdArgs...)
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "Number of lines to show")

	return cmd
}

func installLinuxService() error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root (use sudo)")
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

	// Copy binary to /usr/local/bin if not already there
	targetPath := "/usr/local/bin/selftunnel"
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

	// Create systemd service file
	serviceContent := fmt.Sprintf(`[Unit]
Description=%s
Documentation=https://github.com/asd412id/selftunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s up
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
`, serviceDescription, targetPath, serviceName)

	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
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
	if err := runCommand("systemctl", "enable", serviceName); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("✓ SelfTunnel service installed successfully!")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  selftunnel service start    - Start the service")
	fmt.Println("  selftunnel service stop     - Stop the service")
	fmt.Println("  selftunnel service status   - Check service status")
	fmt.Println("  selftunnel service logs -f  - Follow service logs")
	fmt.Println()
	fmt.Println("Or use systemctl directly:")
	fmt.Printf("  sudo systemctl start %s\n", serviceName)
	fmt.Printf("  sudo systemctl status %s\n", serviceName)
	fmt.Printf("  sudo journalctl -u %s -f\n", serviceName)

	return nil
}

func uninstallLinuxService() error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root (use sudo)")
	}

	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)

	// Check if service exists
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		fmt.Println("Service is not installed.")
		return nil
	}

	// Stop service if running
	fmt.Println("Stopping service...")
	runCommand("systemctl", "stop", serviceName)

	// Disable service
	fmt.Println("Disabling service...")
	runCommand("systemctl", "disable", serviceName)

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
	fmt.Println("✓ SelfTunnel service uninstalled successfully!")
	fmt.Println()
	fmt.Println("Note: The binary at /usr/local/bin/selftunnel was not removed.")
	fmt.Println("      To remove it, run: sudo rm /usr/local/bin/selftunnel")

	return nil
}

func installWindowsService() error {
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
	fmt.Println("Creating Windows service...")

	// sc create selftunnel binPath= "C:\path\to\selftunnel.exe up" start= auto
	binPath := fmt.Sprintf("\"%s\" up", execPath)

	cmd := exec.Command("sc", "create", serviceName,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", serviceDescription)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "1073") {
			fmt.Println("Service already exists. To reinstall, run 'selftunnel service uninstall' first.")
			return nil
		}
		return fmt.Errorf("failed to create service: %s", string(output))
	}

	// Set description
	exec.Command("sc", "description", serviceName, serviceDescription).Run()

	// Configure failure recovery
	exec.Command("sc", "failure", serviceName, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000").Run()

	fmt.Println()
	fmt.Println("✓ SelfTunnel service installed successfully!")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  selftunnel service start   - Start the service")
	fmt.Println("  selftunnel service stop    - Stop the service")
	fmt.Println("  selftunnel service status  - Check service status")
	fmt.Println()
	fmt.Println("Or use Windows Services (services.msc) to manage the service.")

	return nil
}

func uninstallWindowsService() error {
	// Stop service first
	fmt.Println("Stopping service...")
	exec.Command("sc", "stop", serviceName).Run()

	// Delete service
	fmt.Println("Removing service...")
	cmd := exec.Command("sc", "delete", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "1060") {
			fmt.Println("Service does not exist.")
			return nil
		}
		return fmt.Errorf("failed to delete service: %s", string(output))
	}

	fmt.Println()
	fmt.Println("✓ SelfTunnel service uninstalled successfully!")

	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
