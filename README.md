# SelfTunnel

A peer-to-peer mesh VPN that allows you to securely connect multiple devices without requiring a central server for traffic relay. Similar to Tailscale but fully open-source and self-hosted.

## Features

- **P2P Mesh Networking**: Direct device-to-device connections
- **NAT Traversal**: UDP hole punching + STUN for connecting through NATs
- **No IP Public Required**: Only the signaling server needs to be publicly accessible
- **WireGuard-based Encryption**: Industry-standard VPN encryption
- **Cloudflare Workers Signaling**: Free serverless signaling server
- **Full Mesh Topology**: Every node can connect to every other node
- **Local DNS Resolution**: Resolve peer names to virtual IPs (e.g., `my-server.selftunnel`)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    CLOUDFLARE WORKERS                           │
│                   (Signaling Server)                            │
│  • Peer Registration & Discovery                                │
│  • NAT Traversal Coordination                                   │
│  • NO traffic relay - only metadata                             │
└─────────────────────────────────────────────────────────────────┘
                              │
           ┌──────────────────┼──────────────────┐
           ▼                  ▼                  ▼
    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
    │   Node A    │◄──►│   Node B    │◄──►│   Node C    │
    │  (Laptop)   │    │  (Server1)  │    │  (Server2)  │
    │ 10.99.0.1   │    │ 10.99.0.2   │    │ 10.99.0.3   │
    └─────────────┘    └─────────────┘    └─────────────┘
              Direct P2P Encrypted Tunnel
```

## Quick Start

### 1. Deploy Signaling Server (Cloudflare Workers)

```bash
cd worker
npm install -g wrangler
wrangler login

# Create KV namespace (Wrangler v3.60+)
npx wrangler kv namespace create SELFTUNNEL_KV

# Update wrangler.toml with your KV namespace ID
# Then deploy
npx wrangler deploy
```

### 2. Download or Build SelfTunnel

**Option A: Download from releases**
```bash
# Linux
wget https://github.com/asd412id/selftunnel/releases/latest/download/selftunnel-linux-amd64
chmod +x selftunnel-linux-amd64
sudo mv selftunnel-linux-amd64 /usr/local/bin/selftunnel

# Windows - download selftunnel-windows-amd64.exe
```

**Option B: Build from source**
```bash
go build -o selftunnel ./cmd/selftunnel
```

### 3. Initialize a New Network (First Node)

```bash
selftunnel init --name "my-laptop"
```

This will output:
```
Network initialized successfully!

Network ID:     abc123xyz...
Network Secret: secret123...
Public Key:     pubkey123...

Share the Network ID and Secret with other peers to join this network.
```

### 4. Join & Install as Service (Other Nodes) - Recommended

**One-command setup and install:**
```bash
# Linux/macOS
sudo selftunnel service install \
  --network "abc123xyz..." \
  --secret "secret123..." \
  --node-name "my-server"

sudo selftunnel service start

# Windows (Run as Administrator)
selftunnel service install --network "abc123xyz..." --secret "secret123..." --node-name "my-server"
selftunnel service start
```

**Or step by step:**
```bash
# Step 1: Join network (creates config)
selftunnel join --network "abc123xyz..." --secret "secret123..." --name "my-server"

# Step 2: Install service
sudo selftunnel service install

# Step 3: Start service
sudo selftunnel service start
```

### 5. Manual Mode (without service)

```bash
# Run as administrator/root for TUN interface
sudo selftunnel up
```

### 6. Connect via SSH

```bash
# From your laptop, SSH to server using virtual IP
ssh user@10.99.0.2

# Or using peer DNS name (requires DNS setup, see below)
ssh user@my-server.selftunnel
```

## DNS Resolution

SelfTunnel includes a built-in DNS server that resolves peer names to their virtual IPs. This allows you to connect to peers using friendly names instead of remembering IP addresses.

### How It Works

When the daemon starts, it runs a DNS server on port 5353 (configurable). It resolves queries for `<peer-name>.selftunnel` to the peer's virtual IP address.

For example, if you have a peer named `my-server` with virtual IP `10.99.0.2`:
- Query: `my-server.selftunnel` → `10.99.0.2`

### Configure Your System to Use SelfTunnel DNS

**Option 1: Use dig/nslookup directly (testing)**
```bash
# Test DNS resolution
dig @127.0.0.1 -p 5353 my-server.selftunnel
nslookup my-server.selftunnel 127.0.0.1 -port=5353
```

**Option 2: Add to /etc/hosts (simple)**
```bash
# Add entries manually
echo "10.99.0.2 my-server.selftunnel" | sudo tee -a /etc/hosts
```

**Option 3: Configure system resolver (Linux - systemd-resolved)**
```bash
# Create drop-in config for selftunnel domain
sudo mkdir -p /etc/systemd/resolved.conf.d/
sudo tee /etc/systemd/resolved.conf.d/selftunnel.conf <<EOF
[Resolve]
DNS=127.0.0.1:5353
Domains=~selftunnel
EOF

sudo systemctl restart systemd-resolved
```

**Option 4: Configure dnsmasq (if installed)**
```bash
# Add to /etc/dnsmasq.conf
echo "server=/selftunnel/127.0.0.1#5353" | sudo tee -a /etc/dnsmasq.conf
sudo systemctl restart dnsmasq
```

**Option 5: Use port 53 (requires root DNS port)**

Set `dns_port` to `53` in config.json to run DNS on standard port. Then configure your system to use `127.0.0.1` as a DNS server for the `.selftunnel` domain.

### DNS Configuration Options

Add these to your `config.json`:

```json
{
  "dns_enabled": true,
  "dns_port": 5353,
  "dns_suffix": "selftunnel"
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `dns_enabled` | `true` | Enable/disable DNS server |
| `dns_port` | `5353` | UDP port for DNS server |
| `dns_suffix` | `selftunnel` | Domain suffix for peer names |

### Usage Examples

```bash
# SSH using peer name
ssh user@webserver.selftunnel

# Ping a peer
ping database.selftunnel

# Access web service
curl http://api-server.selftunnel:8080

# MySQL connection
mysql -h mysql.selftunnel -u root -p
```

## Commands

| Command | Description |
|---------|-------------|
| `selftunnel init --name <name>` | Initialize a new network |
| `selftunnel join --network <id> --secret <secret> --name <name>` | Join existing network |
| `selftunnel up` | Start the tunnel daemon |
| `selftunnel status` | Show current status |
| `selftunnel peers` | List all peers in the network |
| `selftunnel leave` | Leave the current network |
| `selftunnel generate keys` | Generate a new key pair |

### Service Commands

| Command | Description |
|---------|-------------|
| `selftunnel service install` | Install as system service |
| `selftunnel service install --network <id> --secret <secret> --node-name <name>` | Setup + install in one command |
| `selftunnel service install --name <instance>` | Install named instance (multi-network) |
| `selftunnel service uninstall` | Remove system service |
| `selftunnel service start` | Start the service |
| `selftunnel service stop` | Stop the service |
| `selftunnel service restart` | Restart the service |
| `selftunnel service status` | Show service status |
| `selftunnel service logs` | Show service logs |
| `selftunnel service logs -f` | Follow service logs |

### Multi-Instance Support

Run multiple VPN networks on the same machine:

```bash
# Install first network
sudo selftunnel service install --name office \
  --network "OFFICE_NET_ID" --secret "OFFICE_SECRET" --node-name "my-pc-office"

# Install second network  
sudo selftunnel service install --name home \
  --network "HOME_NET_ID" --secret "HOME_SECRET" --node-name "my-pc-home"

# Manage each instance
sudo selftunnel service start --name office
sudo selftunnel service start --name home
sudo selftunnel service status --name office
sudo selftunnel service logs --name home -f
```

## Configuration

Configuration is stored in:
- **Linux/macOS (root)**: `/etc/selftunnel/config.json`
- **Linux/macOS (user)**: `~/.selftunnel/config.json`
- **Windows**: `%USERPROFILE%\.selftunnel\config.json`

For named instances, config is stored in subdirectory (e.g., `/etc/selftunnel/office/config.json`).

```json
{
  "node_name": "my-laptop",
  "private_key": "...",
  "public_key": "...",
  "network_id": "...",
  "network_secret": "...",
  "virtual_ip": "10.99.0.1",
  "virtual_cidr": "10.99.0.0/24",
  "listen_port": 51820,
  "mtu": 1420,
  "signaling_url": "https://selftunnel-signaling.asdar-binsyam.workers.dev",
  "stun_servers": [
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun.cloudflare.com:3478"
  ],
  "dns_enabled": true,
  "dns_port": 5353,
  "dns_suffix": "selftunnel"
}
```

## Deploy to Ubuntu Server

### Quick Install (Recommended)

```bash
# Download binary
wget https://github.com/asd412id/selftunnel/releases/latest/download/selftunnel-linux-amd64
chmod +x selftunnel-linux-amd64
sudo mv selftunnel-linux-amd64 /usr/local/bin/selftunnel

# Setup + install service in one command
sudo selftunnel service install \
  --network "YOUR_NETWORK_ID" \
  --secret "YOUR_SECRET" \
  --node-name "ubuntu-server"

# Start service
sudo selftunnel service start

# Check status
sudo selftunnel service status
```

### Build from Source

```bash
# Install Go (if not installed)
sudo apt update
sudo apt install -y golang-go

# Clone and build
git clone https://github.com/asd412id/selftunnel.git
cd selftunnel
go build -o selftunnel ./cmd/selftunnel
sudo mv selftunnel /usr/local/bin/

# Setup + install service
sudo selftunnel service install \
  --network "YOUR_NETWORK_ID" \
  --secret "YOUR_SECRET" \
  --node-name "ubuntu-server"

sudo selftunnel service start
```

### Service Management

SelfTunnel includes built-in service management commands (similar to cloudflared):

```bash
# Install service (creates systemd unit and enables autostart)
sudo selftunnel service install

# Uninstall service
sudo selftunnel service uninstall

# Start/Stop/Restart
sudo selftunnel service start
sudo selftunnel service stop
sudo selftunnel service restart

# Check status
sudo selftunnel service status

# View logs (with follow mode)
sudo selftunnel service logs -f
sudo selftunnel service logs -n 100  # last 100 lines
```

### Manual Systemd Setup (Alternative)

1. **Create systemd service file:**

```bash
sudo nano /etc/systemd/system/selftunnel.service
```

2. **Add the following content:**

```ini
[Unit]
Description=SelfTunnel P2P Mesh VPN
Documentation=https://github.com/asd412id/selftunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/selftunnel up
Restart=always
RestartSec=5
LimitNOFILE=65535

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=selftunnel

# Security hardening
NoNewPrivileges=no
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
```

3. **Enable and start the service:**

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable autostart on boot
sudo systemctl enable selftunnel

# Start the service now
sudo systemctl start selftunnel

# Check status
sudo systemctl status selftunnel

# View logs
sudo journalctl -u selftunnel -f
```

### Useful Systemd Commands

```bash
# Start service
sudo systemctl start selftunnel

# Stop service
sudo systemctl stop selftunnel

# Restart service
sudo systemctl restart selftunnel

# Check status
sudo systemctl status selftunnel

# View logs (follow mode)
sudo journalctl -u selftunnel -f

# View last 100 lines of logs
sudo journalctl -u selftunnel -n 100

# Disable autostart
sudo systemctl disable selftunnel
```

### Firewall Configuration (UFW)

```bash
# Allow SelfTunnel UDP port
sudo ufw allow 51820/udp comment "SelfTunnel"

# Allow traffic on virtual network (optional, for inter-node communication)
sudo ufw allow from 10.99.0.0/24 comment "SelfTunnel VPN"

# Reload firewall
sudo ufw reload
```

### Complete Installation Script

Save as `install-selftunnel.sh`:

```bash
#!/bin/bash
set -e

NETWORK_ID="${1:-}"
NETWORK_SECRET="${2:-}"
NODE_NAME="${3:-$(hostname)}"

if [ -z "$NETWORK_ID" ] || [ -z "$NETWORK_SECRET" ]; then
    echo "Usage: $0 <network_id> <network_secret> [node_name]"
    exit 1
fi

echo "=== Installing SelfTunnel ==="

# Install dependencies
sudo apt update
sudo apt install -y curl

# Download binary (replace with your release URL)
echo "Downloading SelfTunnel..."
# Option 1: Download from releases
# wget -O /tmp/selftunnel https://github.com/asd412id/selftunnel/releases/latest/download/selftunnel-linux-amd64

# Option 2: Build from source
sudo apt install -y golang-go git
cd /tmp
git clone https://github.com/asd412id/selftunnel.git || true
cd selftunnel
go build -o selftunnel ./cmd/selftunnel
sudo mv selftunnel /usr/local/bin/

# Make executable
sudo chmod +x /usr/local/bin/selftunnel

# Join network
echo "Joining network..."
selftunnel join --network "$NETWORK_ID" --secret "$NETWORK_SECRET" --name "$NODE_NAME"

# Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/selftunnel.service > /dev/null <<EOF
[Unit]
Description=SelfTunnel P2P Mesh VPN
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/selftunnel up
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable selftunnel
sudo systemctl start selftunnel

# Configure firewall
if command -v ufw &> /dev/null; then
    echo "Configuring firewall..."
    sudo ufw allow 51820/udp comment "SelfTunnel"
    sudo ufw allow from 10.99.0.0/24 comment "SelfTunnel VPN"
fi

echo "=== Installation Complete ==="
echo "Check status: sudo systemctl status selftunnel"
echo "View logs: sudo journalctl -u selftunnel -f"
selftunnel status
```

Run the script:
```bash
chmod +x install-selftunnel.sh
sudo ./install-selftunnel.sh "YOUR_NETWORK_ID" "YOUR_NETWORK_SECRET" "my-ubuntu-server"
```

## How It Works

1. **Registration**: Each node registers with the signaling server, sharing its public key and discovered endpoints
2. **Discovery**: Nodes discover each other through the signaling server
3. **NAT Traversal**: STUN is used to discover public endpoints, then UDP hole punching establishes direct connections
4. **Encryption**: All traffic is encrypted using WireGuard protocol (Noise framework with ChaCha20-Poly1305)
5. **Mesh**: Each node maintains direct connections to all other nodes

## Security

- **X25519 Key Exchange**: Each node has a unique X25519 key pair
- **Network Secret**: Only nodes with the correct network secret can join
- **End-to-End Encryption**: All traffic is encrypted, signaling server sees only metadata
- **No Traffic Relay**: The signaling server never sees your actual network traffic

## Requirements

- Go 1.21+ (for building from source)
- Root/Administrator privileges (for TUN interface)
- Cloudflare account (for signaling server - free tier sufficient)

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Full | Recommended for servers |
| macOS | ✅ Full | Requires sudo |
| Windows | ✅ Full | WinTUN driver embedded (auto-extracted) |

## Limitations

- **Symmetric NAT**: May fail to establish direct connection (fallback to relay planned)
- **Strict Firewalls**: Some corporate firewalls may block UDP traffic

## Troubleshooting

### Service won't start
```bash
# Check logs
sudo journalctl -u selftunnel -n 50

# Check config
cat ~/.selftunnel/config.json

# Test manually
sudo /usr/local/bin/selftunnel up
```

### Cannot connect to peers
```bash
# Check firewall
sudo ufw status

# Check if port is open
sudo ss -ulnp | grep 51820

# Test STUN
selftunnel status
```

### TUN interface not created
```bash
# Check if TUN module is loaded
lsmod | grep tun

# Load TUN module
sudo modprobe tun
```

## Roadmap

- [ ] TURN relay fallback for strict NATs
- [x] DNS resolution for peer names
- [ ] Access control lists
- [ ] Multi-hop routing for partial mesh
- [ ] Mobile support (iOS/Android)
- [ ] Web-based management UI

## License

MIT License
