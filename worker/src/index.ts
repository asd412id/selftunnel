// Cloudflare Worker for SelfTunnel Signaling Server
// Deploy with: wrangler publish

interface Env {
  SELFTUNNEL_KV: KVNamespace;
}

interface Peer {
  name: string;
  public_key: string;
  virtual_ip: string;
  endpoints: string[];
  last_seen: number;
  metadata?: Record<string, string>;
}

interface Network {
  id: string;
  secret_hash: string;
  peers: Record<string, Peer>;
  next_ip: number;
  created_at: number;
}

const NETWORK_TTL = 86400 * 7; // 7 days
const PEER_TTL = 300; // 5 minutes

async function hashSecret(secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(secret);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

async function getNetwork(env: Env, networkId: string): Promise<Network | null> {
  const data = await env.SELFTUNNEL_KV.get(`network:${networkId}`);
  if (!data) return null;
  return JSON.parse(data);
}

async function saveNetwork(env: Env, network: Network): Promise<void> {
  await env.SELFTUNNEL_KV.put(
    `network:${network.id}`,
    JSON.stringify(network),
    { expirationTtl: NETWORK_TTL }
  );
}

async function validateNetwork(env: Env, networkId: string, networkSecret: string): Promise<Network | null> {
  let network = await getNetwork(env, networkId);
  
  if (!network) {
    // Create new network
    const secretHash = await hashSecret(networkSecret);
    network = {
      id: networkId,
      secret_hash: secretHash,
      peers: {},
      next_ip: 2, // Start from .2 (.1 is reserved)
      created_at: Date.now(),
    };
    await saveNetwork(env, network);
    return network;
  }

  // Validate secret
  const providedHash = await hashSecret(networkSecret);
  if (network.secret_hash !== providedHash) {
    return null;
  }

  return network;
}

function allocateIP(network: Network): string {
  const ip = `10.99.0.${network.next_ip}`;
  network.next_ip = (network.next_ip % 254) + 1;
  if (network.next_ip === 1) network.next_ip = 2;
  return ip;
}

function cleanupStalePeers(network: Network): void {
  const now = Date.now();
  for (const [key, peer] of Object.entries(network.peers)) {
    if (now - peer.last_seen > PEER_TTL * 1000) {
      delete network.peers[key];
    }
  }
}

async function handleRegister(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as {
      network_id: string;
      network_secret: string;
      peer: Peer;
    };

    const network = await validateNetwork(env, body.network_id, body.network_secret);
    if (!network) {
      return new Response(JSON.stringify({ success: false, message: 'Invalid network credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    cleanupStalePeers(network);

    // Check if peer already exists
    let virtualIP = body.peer.virtual_ip;
    const existingPeer = network.peers[body.peer.public_key];
    
    if (existingPeer) {
      virtualIP = existingPeer.virtual_ip;
    } else if (!virtualIP) {
      virtualIP = allocateIP(network);
    }

    // Update peer
    network.peers[body.peer.public_key] = {
      name: body.peer.name,
      public_key: body.peer.public_key,
      virtual_ip: virtualIP,
      endpoints: body.peer.endpoints || [],
      last_seen: Date.now(),
      metadata: body.peer.metadata,
    };

    await saveNetwork(env, network);

    return new Response(JSON.stringify({
      success: true,
      virtual_ip: virtualIP,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ success: false, message: 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

async function handleGetPeers(request: Request, env: Env): Promise<Response> {
  try {
    const networkId = request.headers.get('X-Network-ID');
    const networkSecret = request.headers.get('X-Network-Secret');

    if (!networkId || !networkSecret) {
      return new Response(JSON.stringify({ error: 'Missing credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const network = await validateNetwork(env, networkId, networkSecret);
    if (!network) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    cleanupStalePeers(network);
    await saveNetwork(env, network);

    const peers = Object.values(network.peers);

    return new Response(JSON.stringify({ peers }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Internal error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

async function handleHeartbeat(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as {
      network_id: string;
      network_secret: string;
      public_key: string;
      endpoints?: string[];
    };

    const network = await validateNetwork(env, body.network_id, body.network_secret);
    if (!network) {
      return new Response(JSON.stringify({ success: false }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const peer = network.peers[body.public_key];
    if (peer) {
      peer.last_seen = Date.now();
      if (body.endpoints) {
        peer.endpoints = body.endpoints;
      }
      await saveNetwork(env, network);
    }

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ success: false }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

async function handleExchange(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as {
      network_id: string;
      network_secret: string;
      from_public_key: string;
      to_public_key: string;
      endpoints: string[];
    };

    const network = await validateNetwork(env, body.network_id, body.network_secret);
    if (!network) {
      return new Response(JSON.stringify({ success: false }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Store exchange info for the target peer to poll
    const exchangeKey = `exchange:${body.network_id}:${body.to_public_key}:${body.from_public_key}`;
    await env.SELFTUNNEL_KV.put(exchangeKey, JSON.stringify({
      from: body.from_public_key,
      endpoints: body.endpoints,
      timestamp: Date.now(),
    }), { expirationTtl: 60 });

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ success: false }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

async function handleUnregister(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as {
      network_id: string;
      network_secret: string;
      public_key: string;
    };

    const network = await validateNetwork(env, body.network_id, body.network_secret);
    if (!network) {
      return new Response(JSON.stringify({ success: false }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    delete network.peers[body.public_key];
    await saveNetwork(env, network);

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ success: false }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Network-ID, X-Network-Secret',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    let response: Response;

    switch (path) {
      case '/register':
        response = await handleRegister(request, env);
        break;
      case '/peers':
        response = await handleGetPeers(request, env);
        break;
      case '/heartbeat':
        response = await handleHeartbeat(request, env);
        break;
      case '/exchange':
        response = await handleExchange(request, env);
        break;
      case '/unregister':
        response = await handleUnregister(request, env);
        break;
      case '/':
      case '/health':
        response = new Response(JSON.stringify({ 
          status: 'ok', 
          service: 'selftunnel-signaling',
          version: '1.0.0'
        }), {
          headers: { 'Content-Type': 'application/json' },
        });
        break;
      default:
        response = new Response(JSON.stringify({ error: 'Not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
    }

    // Add CORS headers to response
    Object.entries(corsHeaders).forEach(([key, value]) => {
      response.headers.set(key, value);
    });

    return response;
  },
};
