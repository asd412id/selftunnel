# SelfTunnel Signaling Server Deployment

Deploy signaling server untuk koordinasi peer discovery dan relay fallback.

## Arsitektur

```
Internet                         VPS
─────────────────────────────────────────────────────
                            ┌─────────────────────┐
  selftunnel.domain.com     │  Cloudflare Tunnel  │
  ─────────────────────────►│    (cloudflared)    │
        HTTPS/WSS           │        │            │
                            │        ▼            │
                            │  ┌─────────────┐    │
                            │  │  Signaling  │    │
                            │  │   Server    │    │
                            │  │   :8080     │    │
                            │  └─────────────┘    │
                            └─────────────────────┘
```

## Quick Start (Docker + Cloudflare Tunnel)

### 1. Create Cloudflare Tunnel

1. Login ke [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com)
2. Pergi ke **Access** > **Tunnels** > **Create a tunnel**
3. Pilih **Cloudflared** connector
4. Beri nama tunnel: `selftunnel-signaling`
5. Pilih **Docker** sebagai environment
6. Copy token (string panjang setelah `--token`)

### 2. Configure Public Hostname

Di konfigurasi tunnel:
- **Public hostname**: `signaling.yourdomain.com`
- **Service**: `http://signaling-server:8080`

> Note: Gunakan `signaling-server` (nama container), bukan `localhost`

### 3. Deploy

```bash
# Clone repository
git clone https://github.com/asd412id/selftunnel.git
cd selftunnel/deploy/docker

# Set tunnel token
export TUNNEL_TOKEN=eyJhIjoixxxxx...

# Start services
docker compose up -d

# Check logs
docker compose logs -f

# Check health
curl https://signaling.yourdomain.com/health
```

## Management

```bash
# Stop
docker compose down

# Restart
docker compose restart

# Update
docker compose pull
docker compose up -d

# View logs
docker compose logs -f cloudflared
docker compose logs -f signaling-server
```

## Build from Source

```bash
# Build image
docker build -t selftunnel-signaling:latest -f deploy/docker/Dockerfile .

# Run container
docker run -d --name signaling -p 8080:8080 selftunnel-signaling:latest
```

---

## Systemd Deployment (Alternative)

### Automatic Install

```bash
curl -sSL https://raw.githubusercontent.com/asd412id/selftunnel/main/deploy/systemd/install.sh | sudo bash
```

Script ini akan:
- Download binary terbaru
- Membuat user `selftunnel`
- Install dan enable service
- Start service

### Manual Install

```bash
# Download binary
wget https://github.com/asd412id/selftunnel/releases/latest/download/signaling-server-linux-amd64
chmod +x signaling-server-linux-amd64
sudo mv signaling-server-linux-amd64 /usr/local/bin/signaling-server

# Create user
sudo useradd -r -s /bin/false selftunnel

# Install service
sudo cp deploy/systemd/selftunnel-signaling.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now selftunnel-signaling
```

### Service Management

```bash
# Status
sudo systemctl status selftunnel-signaling

# Logs
sudo journalctl -u selftunnel-signaling -f

# Restart
sudo systemctl restart selftunnel-signaling
```

### Uninstall

```bash
curl -sSL https://raw.githubusercontent.com/asd412id/selftunnel/main/deploy/systemd/uninstall.sh | sudo bash
```

---

## Testing

### Health Check

```bash
curl https://signaling.yourdomain.com/health
# {"status":"ok","service":"selftunnel-signaling","version":"2.0.0",...}
```

### WebSocket Relay

```bash
# Install wscat: npm install -g wscat
wscat -c wss://signaling.yourdomain.com/relay
```

---

## Troubleshooting

### Service won't start

```bash
# Check logs
docker compose logs -f

# Run manually for debugging
docker compose run --rm signaling-server
```

### WebSocket not working

Pastikan WebSocket enabled di Cloudflare:
Dashboard > Network > WebSockets = ON

### Connection timeout

```bash
# Test dari server lokal
docker compose exec signaling-server wget -qO- http://localhost:8080/health

# Check tunnel status
docker compose logs cloudflared
```

---

## Update

```bash
cd deploy/docker
docker compose pull
docker compose up -d
```
