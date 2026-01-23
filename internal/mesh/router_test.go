package mesh

import (
	"net"
	"testing"
)

func TestNewRouter(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})
	router := NewRouter(pm)

	if router == nil {
		t.Fatal("NewRouter returned nil")
	}
}

func TestAddAndFindRoute(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})
	router := NewRouter(pm)

	// Add a route
	_, dest, _ := net.ParseCIDR("10.99.0.2/32")
	router.AddRoute(dest, "peer-key", 1, true)

	// Find route
	route := router.FindRoute(net.ParseIP("10.99.0.2"))
	if route == nil {
		t.Fatal("FindRoute returned nil")
	}
	if route.NextHop != "peer-key" {
		t.Errorf("NextHop: got %s, want peer-key", route.NextHop)
	}
	if route.Metric != 1 {
		t.Errorf("Metric: got %d, want 1", route.Metric)
	}
	if !route.Direct {
		t.Error("Direct should be true")
	}
}

func TestFindRouteLongestMatch(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})
	router := NewRouter(pm)

	// Add a broad route
	_, dest1, _ := net.ParseCIDR("10.99.0.0/24")
	router.AddRoute(dest1, "gateway", 2, false)

	// Add a more specific route
	_, dest2, _ := net.ParseCIDR("10.99.0.5/32")
	router.AddRoute(dest2, "direct-peer", 1, true)

	// Should match the more specific route
	route := router.FindRoute(net.ParseIP("10.99.0.5"))
	if route == nil {
		t.Fatal("FindRoute returned nil")
	}
	if route.NextHop != "direct-peer" {
		t.Errorf("Should match more specific route, got %s", route.NextHop)
	}

	// Different IP should match the broad route
	route2 := router.FindRoute(net.ParseIP("10.99.0.10"))
	if route2 == nil {
		t.Fatal("FindRoute returned nil for broad match")
	}
	if route2.NextHop != "gateway" {
		t.Errorf("Should match broad route, got %s", route2.NextHop)
	}
}

func TestFindRouteNoMatch(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})
	router := NewRouter(pm)

	_, dest, _ := net.ParseCIDR("10.99.0.0/24")
	router.AddRoute(dest, "peer", 1, true)

	// IP outside the network
	route := router.FindRoute(net.ParseIP("192.168.1.1"))
	if route != nil {
		t.Error("Should return nil for non-matching IP")
	}
}

func TestRemoveRoute(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})
	router := NewRouter(pm)

	_, dest, _ := net.ParseCIDR("10.99.0.2/32")
	router.AddRoute(dest, "peer", 1, true)

	// Remove
	router.RemoveRoute(dest)

	// Should be gone
	route := router.FindRoute(net.ParseIP("10.99.0.2"))
	if route != nil {
		t.Error("Route should be removed")
	}
}

func TestGetAllRoutes(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})
	router := NewRouter(pm)

	_, dest1, _ := net.ParseCIDR("10.99.0.1/32")
	_, dest2, _ := net.ParseCIDR("10.99.0.2/32")
	_, dest3, _ := net.ParseCIDR("10.99.0.3/32")

	router.AddRoute(dest1, "peer1", 1, true)
	router.AddRoute(dest2, "peer2", 1, true)
	router.AddRoute(dest3, "peer3", 1, true)

	routes := router.GetAllRoutes()
	if len(routes) != 3 {
		t.Errorf("Expected 3 routes, got %d", len(routes))
	}
}

func TestFindNextHop(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})

	// Add peer
	peer := &Peer{
		Name:      "remote",
		PublicKey: "remote-key",
		VirtualIP: "10.99.0.2",
	}
	pm.AddPeer(peer)

	router := NewRouter(pm)

	// Add route for the peer
	_, dest, _ := net.ParseCIDR("10.99.0.2/32")
	router.AddRoute(dest, "remote-key", 1, true)

	// Find next hop
	nextHop := router.FindNextHop(net.ParseIP("10.99.0.2"))
	if nextHop == nil {
		t.Fatal("FindNextHop returned nil")
	}
	if nextHop.Name != "remote" {
		t.Errorf("NextHop name: got %s, want remote", nextHop.Name)
	}
}

func TestFindNextHopNoRoute(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})
	router := NewRouter(pm)

	nextHop := router.FindNextHop(net.ParseIP("10.99.0.5"))
	if nextHop != nil {
		t.Error("Should return nil when no route exists")
	}
}

func TestUpdateRoutesFromPeers(t *testing.T) {
	pm := NewPeerManager(&Peer{Name: "local", PublicKey: "local-key"})

	// Add connected peers
	pm.AddPeer(&Peer{
		Name:      "peer1",
		PublicKey: "key1",
		VirtualIP: "10.99.0.2",
		State:     PeerStateConnected,
	})
	pm.AddPeer(&Peer{
		Name:      "peer2",
		PublicKey: "key2",
		VirtualIP: "10.99.0.3",
		State:     PeerStateConnected,
	})
	pm.AddPeer(&Peer{
		Name:      "peer3",
		PublicKey: "key3",
		VirtualIP: "10.99.0.4",
		State:     PeerStateDisconnected, // Not connected
	})

	router := NewRouter(pm)
	router.UpdateRoutesFromPeers()

	// Should have routes only for connected peers
	routes := router.GetAllRoutes()
	if len(routes) != 2 {
		t.Errorf("Expected 2 routes for connected peers, got %d", len(routes))
	}

	// Verify routes
	route1 := router.FindRoute(net.ParseIP("10.99.0.2"))
	if route1 == nil {
		t.Error("Should have route for peer1")
	}
	route2 := router.FindRoute(net.ParseIP("10.99.0.3"))
	if route2 == nil {
		t.Error("Should have route for peer2")
	}
	route3 := router.FindRoute(net.ParseIP("10.99.0.4"))
	if route3 != nil {
		t.Error("Should not have route for disconnected peer3")
	}
}
