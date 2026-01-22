// Cloudflare Worker for SelfTunnel Signaling Server with WebSocket Relay
// Using Durable Objects for persistent in-memory storage
// Deploy with: wrangler deploy

interface Env {
  SELFTUNNEL_KV: KVNamespace;
  NETWORK_STORE: DurableObjectNamespace;
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

// Relay message types
interface RelayMessage {
  type: 'auth' | 'data' | 'ping' | 'pong' | 'error';
  network_id?: string;
  network_secret?: string;
  public_key?: string;
  to?: string;
  from?: string;
  payload?: string;
  error?: string;
}

const PEER_TTL = 300; // 5 minutes

async function hashSecret(secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(secret);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

// Durable Object for Network Storage
export class NetworkStore {
  state: DurableObjectState;
  network: Network | null = null;
  connections: Map<string, WebSocket> = new Map();

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle WebSocket upgrade for relay
    if (path === '/relay') {
      return this.handleWebSocket(request);
    }

    // Load network from storage if not loaded
    if (!this.network) {
      this.network = await this.state.storage.get('network') || null;
    }

    if (path === '/register') {
      return this.handleRegister(request);
    } else if (path === '/peers') {
      return this.handleGetPeers(request);
    } else if (path === '/heartbeat') {
      return this.handleHeartbeat(request);
    } else if (path === '/unregister') {
      return this.handleUnregister(request);
    }

    return new Response('Not found', { status: 404 });
  }

  async handleRegister(request: Request): Promise<Response> {
    try {
      const body = await request.json() as {
        network_id: string;
        network_secret: string;
        peer: Peer;
      };

      if (!body.peer?.public_key || !body.peer?.name) {
        return new Response(JSON.stringify({ success: false, message: 'Missing peer data' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const secretHash = await hashSecret(body.network_secret);

      // Initialize or validate network
      if (!this.network) {
        this.network = {
          id: body.network_id,
          secret_hash: secretHash,
          peers: {},
          next_ip: 2,
          created_at: Date.now(),
        };
      } else if (this.network.secret_hash !== secretHash) {
        return new Response(JSON.stringify({ success: false, message: 'Invalid credentials' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Cleanup stale peers
      this.cleanupStalePeers();

      // Allocate or reuse IP
      let virtualIP = body.peer.virtual_ip;
      const existingPeer = this.network.peers[body.peer.public_key];
      
      if (existingPeer) {
        virtualIP = existingPeer.virtual_ip;
      } else if (!virtualIP) {
        virtualIP = `10.99.0.${this.network.next_ip}`;
        this.network.next_ip++;
        if (this.network.next_ip > 254) this.network.next_ip = 2;
      }

      this.network.peers[body.peer.public_key] = {
        name: body.peer.name,
        public_key: body.peer.public_key,
        virtual_ip: virtualIP,
        endpoints: body.peer.endpoints || [],
        last_seen: Date.now(),
        metadata: body.peer.metadata,
      };

      await this.state.storage.put('network', this.network);

      return new Response(JSON.stringify({
        success: true,
        virtual_ip: virtualIP,
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (error) {
      console.error('Register error:', error);
      return new Response(JSON.stringify({ success: false, message: 'Internal error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  async handleGetPeers(request: Request): Promise<Response> {
    const secretHash = await hashSecret(request.headers.get('X-Network-Secret') || '');

    if (!this.network || this.network.secret_hash !== secretHash) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    this.cleanupStalePeers();
    await this.state.storage.put('network', this.network);

    const peers = Object.values(this.network.peers);

    return new Response(JSON.stringify({ peers }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  async handleHeartbeat(request: Request): Promise<Response> {
    try {
      const body = await request.json() as {
        network_secret: string;
        public_key: string;
        endpoints?: string[];
      };

      const secretHash = await hashSecret(body.network_secret);

      if (!this.network || this.network.secret_hash !== secretHash) {
        return new Response(JSON.stringify({ success: false }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const peer = this.network.peers[body.public_key];
      if (peer) {
        peer.last_seen = Date.now();
        if (body.endpoints) {
          peer.endpoints = body.endpoints;
        }
        await this.state.storage.put('network', this.network);
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

  async handleUnregister(request: Request): Promise<Response> {
    try {
      const body = await request.json() as {
        network_secret: string;
        public_key: string;
      };

      const secretHash = await hashSecret(body.network_secret);

      if (!this.network || this.network.secret_hash !== secretHash) {
        return new Response(JSON.stringify({ success: false }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      delete this.network.peers[body.public_key];
      await this.state.storage.put('network', this.network);

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

  handleWebSocket(request: Request): Response {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    let authenticated = false;
    let publicKey = '';

    server.accept();

    server.addEventListener('message', async (event) => {
      try {
        const msg: RelayMessage = JSON.parse(event.data as string);

        switch (msg.type) {
          case 'auth': {
            if (!msg.network_secret || !msg.public_key) {
              server.send(JSON.stringify({ type: 'error', error: 'Missing auth fields' }));
              return;
            }

            const secretHash = await hashSecret(msg.network_secret);
            if (!this.network || this.network.secret_hash !== secretHash) {
              server.send(JSON.stringify({ type: 'error', error: 'Invalid credentials' }));
              server.close(4001, 'Unauthorized');
              return;
            }

            authenticated = true;
            publicKey = msg.public_key;
            this.connections.set(publicKey, server);

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

            const targetWs = this.connections.get(msg.to);
            if (targetWs && targetWs.readyState === WebSocket.OPEN) {
              targetWs.send(JSON.stringify({
                type: 'data',
                from: publicKey,
                payload: msg.payload,
              }));
            }
            break;
          }

          case 'ping': {
            server.send(JSON.stringify({ type: 'pong' }));
            break;
          }
        }
      } catch (error) {
        server.send(JSON.stringify({ type: 'error', error: 'Invalid message' }));
      }
    });

    server.addEventListener('close', () => {
      if (authenticated && publicKey) {
        this.connections.delete(publicKey);
      }
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  cleanupStalePeers(): void {
    if (!this.network) return;
    const now = Date.now();
    for (const [key, peer] of Object.entries(this.network.peers)) {
      if (now - peer.last_seen > PEER_TTL * 1000) {
        delete this.network.peers[key];
      }
    }
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

    // Health check
    if (path === '/' || path === '/health') {
      return new Response(JSON.stringify({ 
        status: 'ok', 
        service: 'selftunnel-signaling',
        version: '1.3.0',
        features: ['signaling', 'relay', 'durable-objects'],
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Get network ID from request
    let networkId = '';
    if (request.method === 'GET') {
      networkId = request.headers.get('X-Network-ID') || '';
    } else {
      try {
        const cloned = request.clone();
        const body = await cloned.json() as { network_id?: string };
        networkId = body.network_id || '';
      } catch {
        networkId = '';
      }
    }

    if (!networkId && path !== '/' && path !== '/health') {
      return new Response(JSON.stringify({ error: 'Missing network_id' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Route to Durable Object
    if (networkId) {
      const id = env.NETWORK_STORE.idFromName(networkId);
      const stub = env.NETWORK_STORE.get(id);
      
      const response = await stub.fetch(request);
      
      // Add CORS headers to response
      const newResponse = new Response(response.body, response);
      Object.entries(corsHeaders).forEach(([key, value]) => {
        newResponse.headers.set(key, value);
      });
      
      return newResponse;
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  },
};
