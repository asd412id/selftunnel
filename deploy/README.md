# SelfTunnel Signaling Server Deployment

Deploy signaling server ke VPS untuk koordinasi peer discovery dan relay fallback.

## Arsitektur

```
Internet                         VPS
─────────────────────────────────────────────────────
                            ┌─────────────────────┐
  selftunnel.domain.com     │  Reverse Proxy      │
  ─────────────────────────►│  (Caddy/Nginx/CF)   │
        HTTPS/WSS           │        │            │
                            │        ▼            │
                            │  ┌─────────────┐    │
                            │  │  Signaling  │    │
                            │  │   Server    │    │
                            │  │   :8080     │    │
                            │  └─────────────┘    │
                            └─────────────────────┘
```

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/asd412id/selftunnel.git
cd selftunnel/deploy/docker

# Basic (HTTP only, port 8080)
docker compose up -d

# With HTTPS (Caddy auto-SSL)
# Edit Caddyfile first with your domain
docker compose -f compose.https.yaml up -d
```

### Option 2: Systemd Service

```bash
# One-liner install
curl -sSL https://raw.githubusercontent.com/asd412id/selftunnel/main/deploy/systemd/install.sh | sudo bash

# Or manual:
# Download binary
wget https://github.com/asd412id/selftunnel/releases/latest/download/signaling-server-linux-amd64
chmod +x signaling-server-linux-amd64
sudo mv signaling-server-linux-amd64 /usr/local/bin/signaling-server

# Install service
sudo cp deploy/systemd/selftunnel-signaling.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now selftunnel-signaling
```

### Option 3: Cloudflare Tunnel (No Public IP Needed)

```bash
# Install signaling server first (Option 2)
# Then expose via Cloudflare Tunnel

cloudflared tunnel --url http://localhost:8080
# This gives you a random URL like https://random-words.trycloudflare.com

# For production, create named tunnel:
cloudflared tunnel login
cloudflared tunnel create selftunnel
cloudflared tunnel route dns selftunnel signaling.yourdomain.com
cloudflared tunnel run selftunnel
```

---

## Detailed Setup

### Docker Deployment

#### Basic Setup (HTTP)

```bash
cd deploy/docker
docker compose up -d

# Check logs
docker compose logs -f

# Check health
curl http://localhost:8080/health
```

#### With HTTPS (Caddy)

1. Edit `Caddyfile`:
```
signaling.yourdomain.com {
    reverse_proxy signaling-server:8080
}
```

2. Run:
```bash
docker compose -f compose.https.yaml up -d
```

Caddy akan otomatis mendapatkan SSL certificate dari Let's Encrypt.

#### Build from Source

```bash
# Build image
docker build -t selftunnel-signaling:latest -f deploy/docker/Dockerfile .

# Run container
docker run -d --name signaling -p 8080:8080 selftunnel-signaling:latest
```

---

### Systemd Deployment

#### Automatic Install

```bash
curl -sSL https://raw.githubusercontent.com/asd412id/selftunnel/main/deploy/systemd/install.sh | sudo bash
```

Script ini akan:
- Download binary terbaru
- Membuat user `selftunnel`
- Install dan enable service
- Start service

#### Manual Install

1. Download binary:
```bash
wget https://github.com/asd412id/selftunnel/releases/latest/download/signaling-server-linux-amd64
chmod +x signaling-server-linux-amd64
sudo mv signaling-server-linux-amd64 /usr/local/bin/signaling-server
```

2. Create user:
```bash
sudo useradd -r -s /bin/false selftunnel
```

3. Install service:
```bash
sudo cp deploy/systemd/selftunnel-signaling.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable selftunnel-signaling
sudo systemctl start selftunnel-signaling
```

#### Service Management

```bash
# Status
sudo systemctl status selftunnel-signaling

# Logs
sudo journalctl -u selftunnel-signaling -f

# Restart
sudo systemctl restart selftunnel-signaling

# Stop
sudo systemctl stop selftunnel-signaling
```

#### Uninstall

```bash
curl -sSL https://raw.githubusercontent.com/asd412id/selftunnel/main/deploy/systemd/uninstall.sh | sudo bash
# Or
sudo bash deploy/systemd/uninstall.sh
```

---

### Reverse Proxy Setup

#### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name signaling.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket timeout
        proxy_read_timeout 86400;
    }
}
```

#### Caddy

```
signaling.yourdomain.com {
    reverse_proxy localhost:8080
}
```

#### Cloudflare Tunnel

```bash
# Quick tunnel (testing)
cloudflared tunnel --url http://localhost:8080

# Named tunnel (production)
cloudflared tunnel login
cloudflared tunnel create selftunnel-signaling

# Create config
cat > ~/.cloudflared/config.yml << EOF
tunnel: selftunnel-signaling
credentials-file: /root/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: signaling.yourdomain.com
    service: http://localhost:8080
  - service: http_status:404
EOF

# Route DNS
cloudflared tunnel route dns selftunnel-signaling signaling.yourdomain.com

# Run as service
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

---

## Testing

### Health Check

```bash
curl https://signaling.yourdomain.com/health
# {"status":"ok","service":"selftunnel-signaling","version":"2.0.0",...}
```

### Register Peer

```bash
curl -X POST https://signaling.yourdomain.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "network_id": "test-network",
    "network_secret": "test-secret",
    "peer": {
      "name": "test-peer",
      "public_key": "test-key-123",
      "endpoints": ["1.2.3.4:51820"]
    }
  }'
```

### Get Peers

```bash
curl -H "X-Network-ID: test-network" \
     -H "X-Network-Secret: test-secret" \
     https://signaling.yourdomain.com/peers
```

### WebSocket Relay

```bash
# Install wscat: npm install -g wscat
wscat -c wss://signaling.yourdomain.com/relay
```

---

## Monitoring

### Docker

```bash
# Logs
docker compose logs -f signaling-server

# Stats
docker stats selftunnel-signaling
```

### Systemd

```bash
# Logs
sudo journalctl -u selftunnel-signaling -f

# Resource usage
systemctl status selftunnel-signaling
```

---

## Firewall

### With Reverse Proxy

```bash
# Only allow HTTPS
sudo ufw allow 443/tcp
```

### Direct Access (not recommended)

```bash
sudo ufw allow 8080/tcp
```

### Cloudflare Tunnel

Tidak perlu membuka port apapun! Cloudflared membuat koneksi outbound.

---

## Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u selftunnel-signaling -n 50

# Check if port in use
sudo ss -tulpn | grep 8080

# Run manually for debugging
sudo /usr/local/bin/signaling-server -port 8080
```

### WebSocket not working

1. Pastikan reverse proxy mendukung WebSocket
2. Untuk Cloudflare: Dashboard > Network > WebSockets = ON
3. Check nginx config: `proxy_set_header Upgrade` dan `Connection "upgrade"`

### High memory/CPU

```bash
# Check connections
curl http://localhost:8080/health | jq .stats
```

### Connection timeout

```bash
# Test dari server lokal
curl http://localhost:8080/health

# Test dari luar
curl https://signaling.yourdomain.com/health

# Check firewall
sudo ufw status
```

---

## Update

### Docker

```bash
cd deploy/docker
docker compose pull
docker compose up -d
```

### Systemd

```bash
# Download new binary
wget https://github.com/asd412id/selftunnel/releases/latest/download/signaling-server-linux-amd64
chmod +x signaling-server-linux-amd64
sudo mv signaling-server-linux-amd64 /usr/local/bin/signaling-server

# Restart service
sudo systemctl restart selftunnel-signaling
```
