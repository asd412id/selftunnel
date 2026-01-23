# SelfTunnel

A peer-to-peer mesh VPN that allows you to securely connect multiple devices without requiring a central server for traffic relay. Similar to Tailscale but fully open-source and self-hosted.

## Features

- **P2P Mesh Networking**: Direct device-to-device connections
- **NAT Traversal**: UDP hole punching + STUN for connecting through NATs
- **Relay Fallback**: Automatic relay when direct connection fails (symmetric NAT)
- **DNS Resolution**: Access peers by name (e.g., `ping myserver.selftunnel`)
- **No Public IP Required**: Only the signaling server needs to be publicly accessible
- **WireGuard-based Encryption**: Industry-standard VPN encryption
- **Self-hosted Signaling Server**: Lightweight Go server included
- **Full Mesh Topology**: Every node can connect to every other node

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SIGNALING SERVER                              │
│              (Self-hosted Go server)                             │
│  • Peer Registration & Discovery                                │
│  • NAT Traversal Coordination                                   │
│  • Relay fallback for symmetric NAT                             │
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

### 1. Deploy Signaling Server

The signaling server coordinates peer discovery and provides relay fallback. Choose one of these options:

**Option A: Use Public Signaling Server (Easiest)**

SelfTunnel comes pre-configured with a public signaling server. Just skip to step 2!

**Option B: Deploy to Cloudflare Workers (Recommended for Production)**

Deploy your own signaling server on Cloudflare Workers for free:

```bash
# Install Wrangler CLI
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Deploy
cd deploy/cloudflare-worker
wrangler deploy
```

This gives you a URL like `https://selftunnel-signaling.YOUR_SUBDOMAIN.workers.dev`.

See [deploy/cloudflare-worker/README.md](deploy/cloudflare-worker/README.md) for detailed instructions.

**Option C: Self-host Go Binary**

```bash
# Download
wget https://github.com/asd412id/selftunnel/releases/latest/download/signaling-server-linux-amd64
chmod +x signaling-server-linux-amd64
./signaling-server-linux-amd64 --port 8080

# Or build from source
go build -o signaling-server ./cmd/signaling-server
./signaling-server --port 8080
```

**Option D: Run with systemd**
```bash
# Create service file
sudo tee /etc/systemd/system/selftunnel-signaling.service > /dev/null <<EOF
[Unit]
Description=SelfTunnel Signaling Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/signaling-server --port 8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now selftunnel-signaling
```

**Option E: Run with Docker**
```bash
# Build image
docker build -t selftunnel-signaling -f Dockerfile.signaling .

# Run container
docker run -d --name signaling -p 8080:8080 selftunnel-signaling
```

**Reverse Proxy (for self-hosted options)**

Use nginx or caddy to add HTTPS:
```nginx
server {
    listen 443 ssl;
    server_name signaling.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
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
  "signaling_url": "https://selftunnel-signaling.YOUR_SUBDOMAIN.workers.dev",
  "stun_servers": [
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun.cloudflare.com:3478"
  ]
}
```

### Custom Signaling Server

To use your own signaling server, specify `--signaling-url` when initializing:

```bash
# Using Cloudflare Worker
selftunnel init --name "my-laptop" --signaling-url "https://selftunnel-signaling.YOUR_SUBDOMAIN.workers.dev"

# Using self-hosted server
selftunnel init --name "my-laptop" --signaling-url "https://signaling.yourdomain.com"
```

Or edit the config file directly after initialization.


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
- A server with public IP for signaling server (any VPS works)

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Full | Recommended for servers |
| macOS | ✅ Full | Requires sudo |
| Windows | ✅ Full | WinTUN driver embedded (auto-extracted) |

## Limitations

- **Strict Firewalls**: Some corporate firewalls may block UDP traffic (relay still works over WebSocket)

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

- [x] ~~TURN relay fallback for strict NATs~~ ✅ Implemented
- [x] ~~DNS resolution for peer names~~ ✅ Implemented (e.g., `ping myserver.selftunnel`)
- [ ] Access control lists
- [ ] Multi-hop routing for partial mesh
- [ ] Mobile support (iOS/Android)
- [ ] Web-based management UI

## License

MIT License
