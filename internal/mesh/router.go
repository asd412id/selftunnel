package mesh

import (
	"net"
	"sync"
)

type RouteEntry struct {
	Destination *net.IPNet
	NextHop     string // Public key of next hop peer
	Metric      int
	Direct      bool // Direct connection or via relay
}

type Router struct {
	routes      map[string]*RouteEntry
	peerManager *PeerManager
	mu          sync.RWMutex
}

func NewRouter(pm *PeerManager) *Router {
	return &Router{
		routes:      make(map[string]*RouteEntry),
		peerManager: pm,
	}
}

// AddRoute adds a route to the routing table
func (r *Router) AddRoute(dest *net.IPNet, nextHop string, metric int, direct bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := dest.String()
	r.routes[key] = &RouteEntry{
		Destination: dest,
		NextHop:     nextHop,
		Metric:      metric,
		Direct:      direct,
	}
}

// RemoveRoute removes a route from the routing table
func (r *Router) RemoveRoute(dest *net.IPNet) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.routes, dest.String())
}

// FindRoute finds the best route for a destination IP
func (r *Router) FindRoute(ip net.IP) *RouteEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestRoute *RouteEntry
	var bestMaskLen int

	for _, route := range r.routes {
		if route.Destination.Contains(ip) {
			maskLen, _ := route.Destination.Mask.Size()
			if bestRoute == nil || maskLen > bestMaskLen {
				bestRoute = route
				bestMaskLen = maskLen
			}
		}
	}

	return bestRoute
}

// FindNextHop returns the peer to send packets to for a given destination
func (r *Router) FindNextHop(ip net.IP) *Peer {
	route := r.FindRoute(ip)
	if route == nil {
		return nil
	}

	return r.peerManager.GetPeer(route.NextHop)
}

// GetAllRoutes returns all routes
func (r *Router) GetAllRoutes() []*RouteEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*RouteEntry, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route)
	}
	return routes
}

// UpdateRoutesFromPeers updates routes based on connected peers
func (r *Router) UpdateRoutesFromPeers() {
	peers := r.peerManager.GetConnectedPeers()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear existing peer routes
	for key, route := range r.routes {
		if route.Direct {
			delete(r.routes, key)
		}
	}

	// Add routes for each connected peer's virtual IP
	for _, peer := range peers {
		peer.mu.RLock()
		virtualIP := peer.VirtualIP
		publicKey := peer.PublicKey
		peer.mu.RUnlock()

		if virtualIP == "" {
			continue
		}

		ip := net.ParseIP(virtualIP)
		if ip == nil {
			continue
		}

		// Create /32 route for the peer
		dest := &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}

		r.routes[dest.String()] = &RouteEntry{
			Destination: dest,
			NextHop:     publicKey,
			Metric:      1,
			Direct:      true,
		}
	}
}

// BuildMeshRoutes builds full mesh routes considering multi-hop
func (r *Router) BuildMeshRoutes() {
	r.UpdateRoutesFromPeers()

	// For a full mesh, every peer should be directly reachable
	// In case of partial connectivity, we could implement multi-hop here
	// For now, we only support direct connections
}
