package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	DefaultListenPort   = 51820
	DefaultMTU          = 1420
	DefaultKeepalive    = 25
	DefaultVirtualCIDR  = "10.99.0.0/24"
	DefaultSignalingURL = "https://selftunnel-signaling.asdar-binsyam.workers.dev"
)

type Config struct {
	// Node identity
	NodeName   string `json:"node_name"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`

	// Network settings
	NetworkID     string `json:"network_id"`
	NetworkSecret string `json:"network_secret"`
	VirtualIP     string `json:"virtual_ip"`
	VirtualCIDR   string `json:"virtual_cidr"`

	// Connection settings
	ListenPort int `json:"listen_port"`
	MTU        int `json:"mtu"`
	Keepalive  int `json:"keepalive"`

	// Signaling server
	SignalingURL string `json:"signaling_url"`

	// STUN servers for NAT traversal
	STUNServers []string `json:"stun_servers"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenPort:   DefaultListenPort,
		MTU:          DefaultMTU,
		Keepalive:    DefaultKeepalive,
		VirtualCIDR:  DefaultVirtualCIDR,
		SignalingURL: DefaultSignalingURL,
		STUNServers: []string{
			"stun:stun.l.google.com:19302",
			"stun:stun1.l.google.com:19302",
			"stun:stun.cloudflare.com:3478",
		},
	}
}

func ConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configDir := filepath.Join(homeDir, ".selftunnel")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}
	return configDir, nil
}

func ConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func Load() (*Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Save() error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}
