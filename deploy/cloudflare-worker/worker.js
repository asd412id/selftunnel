/**
 * SelfTunnel Signaling Server - Cloudflare Worker
 * 
 * This worker provides signaling and relay functionality for SelfTunnel P2P mesh VPN.
 * Uses Durable Objects for state persistence and WebSocket relay.
 * 
 * Features:
 * - Peer registration and discovery
 * - WebSocket relay for NAT traversal
 * - Punch coordination for hole punching
 * - Auto-cleanup of stale peers
 */

const PEER_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Utility functions
function hashSecret(secret) {
  const encoder = new TextEncoder();
  const data = encoder.encode(secret);
  return crypto.subtle.digest('SHA-256', data).then(hash => {
    return btoa(String.fromCharCode(...new Uint8Array(hash)));
  });
}

function truncate(s, maxLen) {
  if (!s) return '';
  return s.length <= maxLen ? s : s.substring(0, maxLen);
}

function allocateIP(nextIP) {
  const ip = `10.99.0.${nextIP}`;
  let newNextIP = nextIP + 1;
  if (newNextIP > 254) newNextIP = 2;
  return { ip, nextIP: newNextIP };
}

function isIPInUse(peers, ip, excludePublicKey) {
  for (const [pubKey, peer] of Object.entries(peers)) {
    if (pubKey !== excludePublicKey && peer.virtualIP === ip) {
      return true;
    }
  }
  return false;
}

function allocateUniqueIP(peers, startNextIP) {
  let nextIP = startNextIP;
  for (let i = 0; i < 253; i++) {
    const ip = `10.99.0.${nextIP}`;
    nextIP++;
    if (nextIP > 254) nextIP = 2;
    if (!isIPInUse(peers, ip, '')) {
      return { ip, nextIP };
    }
  }
  return allocateIP(startNextIP);
}

function cleanupStalePeers(peers) {
  const now = Date.now();
  const cleaned = {};
  for (const [key, peer] of Object.entries(peers)) {
    if (now - peer.lastSeen <= PEER_TTL_MS) {
      cleaned[key] = peer;
    }
  }
  return cleaned;
}

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Network-ID, X-Network-Secret',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders,
    },
  });
}

// Durable Object for network state
export class NetworkState {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.connections = new Map(); // publicKey -> WebSocket
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle WebSocket upgrade for relay
    if (request.headers.get('Upgrade') === 'websocket') {
      return this.handleWebSocket(request);
    }

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    switch (path) {
      case '/register':
        return this.handleRegister(request);
      case '/peers':
        return this.handlePeers(request);
      case '/heartbeat':
        return this.handleHeartbeat(request);
      case '/unregister':
        return this.handleUnregister(request);
      default:
        return jsonResponse({ error: 'Not found' }, 404);
    }
  }

  async handleRegister(request) {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method not allowed' }, 405);
    }

    const body = await request.json();
    const { network_id, network_secret, peer } = body;

    if (!peer || !peer.public_key || !peer.name) {
      return jsonResponse({ success: false, message: 'Missing peer data' }, 400);
    }

    const secretHash = await hashSecret(network_secret);

    // Get or initialize network state
    let network = await this.state.storage.get('network');
    if (!network) {
      network = {
        id: network_id,
        secretHash,
        peers: {},
        nextIP: 2,
        createdAt: Date.now(),
      };
    }

    // Validate secret
    if (network.secretHash !== secretHash) {
      return jsonResponse({ success: false, message: 'Invalid credentials' }, 401);
    }

    // Cleanup stale peers
    network.peers = cleanupStalePeers(network.peers);

    // Allocate or reuse IP
    let virtualIP;
    const existingPeer = network.peers[peer.public_key];
    
    if (existingPeer) {
      virtualIP = existingPeer.virtualIP;
    } else if (peer.virtual_ip && !isIPInUse(network.peers, peer.virtual_ip, peer.public_key)) {
      virtualIP = peer.virtual_ip;
    } else {
      const allocated = allocateUniqueIP(network.peers, network.nextIP);
      virtualIP = allocated.ip;
      network.nextIP = allocated.nextIP;
    }

    // Check if name is already in use
    for (const [pk, existingPeer] of Object.entries(network.peers)) {
      if (pk !== peer.public_key && existingPeer.name.toLowerCase() === peer.name.toLowerCase()) {
        return jsonResponse({
          error: `Node name '${peer.name}' is already in use by another peer. Please use a unique name.`,
        }, 409);
      }
    }

    // Register peer
    network.peers[peer.public_key] = {
      name: peer.name,
      publicKey: peer.public_key,
      virtualIP,
      endpoints: peer.endpoints || [],
      lastSeen: Date.now(),
      metadata: peer.metadata || {},
    };

    await this.state.storage.put('network', network);

    console.log(`[${truncate(network_id, 8)}] Registered peer: ${peer.name} (${virtualIP}) - ${truncate(peer.public_key, 16)}`);

    return jsonResponse({ success: true, virtual_ip: virtualIP });
  }

  async handlePeers(request) {
    if (request.method !== 'GET') {
      return jsonResponse({ error: 'Method not allowed' }, 405);
    }

    const networkSecret = request.headers.get('X-Network-Secret');
    if (!networkSecret) {
      return jsonResponse({ error: 'Missing credentials' }, 400);
    }

    const secretHash = await hashSecret(networkSecret);
    const network = await this.state.storage.get('network');

    if (!network || network.secretHash !== secretHash) {
      return jsonResponse({ error: 'Invalid credentials' }, 401);
    }

    // Cleanup and return peers
    network.peers = cleanupStalePeers(network.peers);
    await this.state.storage.put('network', network);

    const peers = Object.values(network.peers).map(p => ({
      name: p.name,
      public_key: p.publicKey,
      virtual_ip: p.virtualIP,
      endpoints: p.endpoints,
      last_seen: p.lastSeen,
      metadata: p.metadata,
    }));

    return jsonResponse({ peers });
  }

  async handleHeartbeat(request) {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method not allowed' }, 405);
    }

    const body = await request.json();
    const { network_secret, public_key, endpoints } = body;

    const secretHash = await hashSecret(network_secret);
    const network = await this.state.storage.get('network');

    if (!network || network.secretHash !== secretHash) {
      return jsonResponse({ success: false }, 401);
    }

    if (network.peers[public_key]) {
      network.peers[public_key].lastSeen = Date.now();
      if (endpoints && endpoints.length > 0) {
        network.peers[public_key].endpoints = endpoints;
      }
      await this.state.storage.put('network', network);
    }

    return jsonResponse({ success: true });
  }

  async handleUnregister(request) {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method not allowed' }, 405);
    }

    const body = await request.json();
    const { network_secret, public_key, peer_name } = body;

    const secretHash = await hashSecret(network_secret);
    const network = await this.state.storage.get('network');

    if (!network || network.secretHash !== secretHash) {
      return jsonResponse({ success: false }, 401);
    }

    if (public_key) {
      delete network.peers[public_key];
    } else if (peer_name) {
      for (const [k, p] of Object.entries(network.peers)) {
        if (p.name === peer_name) {
          delete network.peers[k];
          break;
        }
      }
    }

    await this.state.storage.put('network', network);
    return jsonResponse({ success: true });
  }

  async handleWebSocket(request) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    let authenticated = false;
    let publicKey = '';

    server.accept();

    server.addEventListener('message', async (event) => {
      try {
        const msg = JSON.parse(event.data);

        switch (msg.type) {
          case 'auth': {
            if (!msg.network_secret || !msg.public_key) {
              server.send(JSON.stringify({ type: 'error', error: 'Missing auth fields' }));
              return;
            }

            const secretHash = await hashSecret(msg.network_secret);
            const network = await this.state.storage.get('network');

            if (!network || network.secretHash !== secretHash) {
              server.send(JSON.stringify({ type: 'error', error: 'Invalid credentials' }));
              server.close();
              return;
            }

            authenticated = true;
            publicKey = msg.public_key;
            this.connections.set(publicKey, server);

            console.log(`[Relay] Connected: ${truncate(publicKey, 16)}`);
            server.send(JSON.stringify({ type: 'auth', public_key: publicKey }));
            break;
          }

          case 'data': {
            if (!authenticated) {
              server.send(JSON.stringify({ type: 'error', error: 'Not authenticated' }));
              return;
            }

            if (!msg.to || !msg.payload) {
              server.send(JSON.stringify({ type: 'error', error: 'Missing to or payload' }));
              return;
            }

            const targetConn = this.connections.get(msg.to);
            if (targetConn && targetConn.readyState === WebSocket.OPEN) {
              targetConn.send(JSON.stringify({
                type: 'data',
                from: publicKey,
                payload: msg.payload,
              }));
            }
            break;
          }

          case 'punch': {
            if (!authenticated) {
              server.send(JSON.stringify({ type: 'error', error: 'Not authenticated' }));
              return;
            }

            if (!msg.to) {
              server.send(JSON.stringify({ type: 'error', error: 'Missing target peer' }));
              return;
            }

            const targetConn = this.connections.get(msg.to);
            if (targetConn && targetConn.readyState === WebSocket.OPEN) {
              targetConn.send(JSON.stringify({
                type: 'punch',
                from: publicKey,
                endpoints: msg.endpoints,
              }));
              server.send(JSON.stringify({ type: 'punch_ack', to: msg.to }));
              console.log(`[Punch] ${truncate(publicKey, 16)} -> ${truncate(msg.to, 16)}`);
            } else {
              server.send(JSON.stringify({ type: 'error', error: 'Target peer not connected to relay' }));
            }
            break;
          }

          case 'ping':
            server.send(JSON.stringify({ type: 'pong' }));
            break;
        }
      } catch (err) {
        server.send(JSON.stringify({ type: 'error', error: 'Invalid message format' }));
      }
    });

    server.addEventListener('close', () => {
      if (publicKey) {
        this.connections.delete(publicKey);
        console.log(`[Relay] Disconnected: ${truncate(publicKey, 16)}`);
      }
    });

    server.addEventListener('error', () => {
      if (publicKey) {
        this.connections.delete(publicKey);
      }
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }
}

// Main worker entry point
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Health check
    if (path === '/' || path === '/health') {
      return jsonResponse({
        status: 'ok',
        service: 'selftunnel-signaling',
        version: '2.0.0-cf',
        platform: 'cloudflare-workers',
        features: ['signaling', 'relay', 'websocket', 'durable-objects'],
      });
    }

    // Get network ID from various sources
    let networkId = url.searchParams.get('network_id') || request.headers.get('X-Network-ID');
    
    // For POST requests, try to get from body
    if (!networkId && request.method === 'POST') {
      const clonedRequest = request.clone();
      try {
        const body = await clonedRequest.json();
        networkId = body.network_id;
      } catch (e) {
        // Ignore parse errors
      }
    }

    if (!networkId) {
      return jsonResponse({ error: 'Missing network_id' }, 400);
    }

    // Route to Durable Object for this network
    const id = env.NETWORK_STATE.idFromName(networkId);
    const stub = env.NETWORK_STATE.get(id);

    // Clone request for Durable Object
    const newUrl = new URL(request.url);
    newUrl.pathname = path;

    return stub.fetch(new Request(newUrl, request));
  },
};
