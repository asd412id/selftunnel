# SelfTunnel Signaling Server - Cloudflare Worker

Deploy the SelfTunnel signaling server on Cloudflare Workers with Durable Objects for state persistence.

## Features

- **Serverless**: No server management, auto-scaling
- **Global Edge**: Low latency worldwide via Cloudflare's edge network
- **Persistent State**: Uses Durable Objects for network/peer state
- **WebSocket Relay**: Full relay support for NAT traversal
- **Free Tier Friendly**: Works within Cloudflare Workers free tier for small networks

## Prerequisites

1. [Cloudflare account](https://dash.cloudflare.com/sign-up)
2. [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)

```bash
npm install -g wrangler
```

## Deploy

### 1. Login to Cloudflare

```bash
wrangler login
```

### 2. Deploy the Worker

```bash
cd deploy/cloudflare-worker
wrangler deploy
```

This will output your worker URL like:
```
https://selftunnel-signaling.<your-subdomain>.workers.dev
```

### 3. Configure SelfTunnel to Use Your Worker

```bash
# When initializing a new network
selftunnel init --name "my-node" --signaling-url "https://selftunnel-signaling.YOUR_SUBDOMAIN.workers.dev"

# Or edit existing config
# Edit ~/.selftunnel/config.json and set:
# "signaling_url": "https://selftunnel-signaling.YOUR_SUBDOMAIN.workers.dev"
```

## Custom Domain (Optional)

To use a custom domain like `signaling.yourdomain.com`:

1. Add your domain to Cloudflare
2. Uncomment and edit the `routes` section in `wrangler.toml`:

```toml
routes = [
  { pattern = "signaling.yourdomain.com", custom_domain = true }
]
```

3. Redeploy:

```bash
wrangler deploy
```

## Monitoring

View real-time logs:

```bash
wrangler tail
```

## Pricing

Cloudflare Workers pricing (as of 2024):

| Tier | Requests/day | Durable Objects | WebSocket |
|------|--------------|-----------------|-----------|
| Free | 100,000 | 1GB storage | Included |
| Paid ($5/mo) | 10M+ | Pay-as-you-go | Included |

For most personal/small team use cases, the free tier is sufficient.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Cloudflare Edge Network                   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │  Worker Script  │───▶│  Durable Object (NetworkState)  │ │
│  │  (Stateless)    │    │  - Peer registry                │ │
│  │  - Routing      │    │  - WebSocket connections        │ │
│  │  - Auth         │    │  - Relay messages               │ │
│  └─────────────────┘    └─────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌─────────┐     ┌─────────┐     ┌─────────┐
        │ Node A  │     │ Node B  │     │ Node C  │
        └─────────┘     └─────────┘     └─────────┘
```

## Troubleshooting

### "Durable Object not found"

Make sure migrations are applied:

```bash
wrangler deploy
```

### WebSocket connection fails

Check that your client supports the Cloudflare WebSocket protocol. The worker URL must be accessed over HTTPS.

### Rate limiting

If you hit rate limits on the free tier, consider:
1. Upgrading to paid tier
2. Increasing heartbeat interval in client config
3. Self-hosting the Go signaling server instead
