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
	DefaultSignalingURL = "https://selftunnel.maccaqe.id"
	DefaultDNSPort      = 53
	DefaultDNSSuffix    = "selftunnel"
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
	ListenPort  int  `json:"listen_port"`
	MTU         int  `json:"mtu"`
	Keepalive   int  `json:"keepalive"`
	UseNativeWG bool `json:"use_native_wg"` // Use native wireguard-go instead of custom implementation

	// Signaling server
	SignalingURL string `json:"signaling_url"`

	// STUN servers for NAT traversal
	STUNServers []string `json:"stun_servers"`

	// DNS settings
	DNSEnabled bool   `json:"dns_enabled"`
	DNSPort    int    `json:"dns_port"`
	DNSSuffix  string `json:"dns_suffix"`
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
		DNSEnabled: true,
		DNSPort:    DefaultDNSPort,
		DNSSuffix:  DefaultDNSSuffix,
	}
}

func ConfigDir() (string, error) {
	return ConfigDirForInstance("")
}

func ConfigDirForInstance(instanceName string) (string, error) {
	var configDir string

	// On Linux/macOS running as root, use /etc/selftunnel
	// Otherwise use ~/.selftunnel
	if os.Geteuid() == 0 {
		configDir = "/etc/selftunnel"
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		configDir = filepath.Join(homeDir, ".selftunnel")
	}

	// If instance name provided, use subdirectory
	if instanceName != "" {
		configDir = filepath.Join(configDir, instanceName)
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}
	return configDir, nil
}

func ConfigPath() (string, error) {
	return ConfigPathForInstance("")
}

func ConfigPathForInstance(instanceName string) (string, error) {
	dir, err := ConfigDirForInstance(instanceName)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func Load() (*Config, error) {
	return LoadForInstance("")
}

func LoadForInstance(instanceName string) (*Config, error) {
	path, err := ConfigPathForInstance(instanceName)
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
	return c.SaveForInstance("")
}

func (c *Config) SaveForInstance(instanceName string) error {
	path, err := ConfigPathForInstance(instanceName)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}
