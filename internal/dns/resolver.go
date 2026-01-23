package dns

import (
	"log"
	"strings"

	"github.com/selftunnel/selftunnel/internal/mesh"
)

// MeshResolver adapts PeerManager to the PeerResolver interface
type MeshResolver struct {
	pm *mesh.PeerManager
}

// NewMeshResolver creates a new resolver backed by PeerManager
func NewMeshResolver(pm *mesh.PeerManager) *MeshResolver {
	return &MeshResolver{pm: pm}
}

// GetPeerByName looks up a peer's virtual IP by name
func (r *MeshResolver) GetPeerByName(name string) (virtualIP string, found bool) {
	peer := r.pm.GetPeerByName(name)
	if peer == nil {
		// Debug: log available peers when lookup fails
		allPeers := r.pm.GetAllPeers()
		peerNames := make([]string, 0, len(allPeers))
		for _, p := range allPeers {
			peerNames = append(peerNames, p.Name)
		}
		log.Printf("[DNS] Peer '%s' not found. Available peers: %v", name, peerNames)
		return "", false
	}
	return peer.VirtualIP, true
}

// GetLocalPeer returns the local peer's name and virtual IP
func (r *MeshResolver) GetLocalPeer() (name string, virtualIP string) {
	local := r.pm.LocalPeer()
	if local == nil {
		return "", ""
	}
	return local.Name, local.VirtualIP
}

// ListAllPeers returns all peer names (for debugging)
func (r *MeshResolver) ListAllPeers() []string {
	allPeers := r.pm.GetAllPeers()
	names := make([]string, 0, len(allPeers)+1)

	// Add local peer
	if local := r.pm.LocalPeer(); local != nil {
		names = append(names, strings.ToLower(local.Name))
	}

	for _, p := range allPeers {
		names = append(names, strings.ToLower(p.Name))
	}
	return names
}
