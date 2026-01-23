package wintun

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

//go:embed dll/wintun.dll
var wintunDLL embed.FS

const dllName = "wintun.dll"

// EnsureWinTUN extracts wintun.dll to system directory if needed
// DEPRECATED: Use ExtractToPath for proper DLL placement.
// The wintun library only searches Application Dir and System32.
func EnsureWinTUN() error {
	if runtime.GOOS != "windows" {
		return nil
	}

	// Check if wintun.dll already exists in System32
	systemPath := filepath.Join(os.Getenv("SystemRoot"), "System32", dllName)
	if fileExists(systemPath) {
		return nil
	}

	// Try to extract to temp directory (legacy behavior, may not work)
	tempDir := os.TempDir()
	dllPath := filepath.Join(tempDir, dllName)

	if fileExists(dllPath) {
		return nil
	}

	// Extract embedded DLL
	data, err := wintunDLL.ReadFile("dll/wintun.dll")
	if err != nil {
		return fmt.Errorf("failed to read embedded wintun.dll: %w", err)
	}

	if err := os.WriteFile(dllPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write wintun.dll: %w", err)
	}

	// Add to PATH (note: this may not help as wintun library doesn't use PATH)
	os.Setenv("PATH", tempDir+";"+os.Getenv("PATH"))

	return nil
}

// ExtractToPath extracts the embedded wintun.dll to the specified path
func ExtractToPath(dllPath string) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	// Read embedded DLL
	data, err := wintunDLL.ReadFile("dll/wintun.dll")
	if err != nil {
		return fmt.Errorf("failed to read embedded wintun.dll: %w", err)
	}

	// Ensure parent directory exists
	dir := filepath.Dir(dllPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write DLL to target path
	if err := os.WriteFile(dllPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write wintun.dll to %s: %w", dllPath, err)
	}

	return nil
}

// GetEmbeddedDLL returns the embedded wintun.dll data
func GetEmbeddedDLL() ([]byte, error) {
	return wintunDLL.ReadFile("dll/wintun.dll")
}

// InstallWinTUN installs wintun.dll to System32 (requires admin)
func InstallWinTUN() error {
	if runtime.GOOS != "windows" {
		return nil
	}

	systemPath := filepath.Join(os.Getenv("SystemRoot"), "System32", dllName)

	if fileExists(systemPath) {
		fmt.Println("WinTUN is already installed.")
		return nil
	}

	data, err := wintunDLL.ReadFile("dll/wintun.dll")
	if err != nil {
		return fmt.Errorf("failed to read embedded wintun.dll: %w", err)
	}

	if err := os.WriteFile(systemPath, data, 0644); err != nil {
		return fmt.Errorf("failed to install wintun.dll (run as Administrator): %w", err)
	}

	fmt.Printf("WinTUN installed to %s\n", systemPath)
	return nil
}

// UninstallWinTUN removes wintun.dll from System32
func UninstallWinTUN() error {
	if runtime.GOOS != "windows" {
		return nil
	}

	systemPath := filepath.Join(os.Getenv("SystemRoot"), "System32", dllName)

	if !fileExists(systemPath) {
		fmt.Println("WinTUN is not installed.")
		return nil
	}

	if err := os.Remove(systemPath); err != nil {
		return fmt.Errorf("failed to remove wintun.dll (run as Administrator): %w", err)
	}

	fmt.Println("WinTUN uninstalled successfully.")
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
