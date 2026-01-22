package dns

import (
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
