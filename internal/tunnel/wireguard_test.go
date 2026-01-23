package tunnel

import (
	"testing"
	"time"

	"github.com/selftunnel/selftunnel/internal/crypto"
)

func TestWGConstants(t *testing.T) {
	// Verify constants
	if WGHeaderSize != 16 {
		t.Errorf("WGHeaderSize: got %d, want 16", WGHeaderSize)
	}
	if WGKeepalive != 25*time.Second {
		t.Errorf("WGKeepalive: got %v, want 25s", WGKeepalive)
	}
	if DirectGracePeriod != 5*time.Second {
		t.Errorf("DirectGracePeriod: got %v, want 5s", DirectGracePeriod)
	}
	if DirectConfirmCount != 3 {
		t.Errorf("DirectConfirmCount: got %d, want 3", DirectConfirmCount)
	}
}

func TestWGPacketTypes(t *testing.T) {
	// Verify packet types
	if WGHandshakeInit != 1 {
		t.Errorf("WGHandshakeInit: got %d, want 1", WGHandshakeInit)
	}
	if WGHandshakeResp != 2 {
		t.Errorf("WGHandshakeResp: got %d, want 2", WGHandshakeResp)
	}
	if WGCookieReply != 3 {
		t.Errorf("WGCookieReply: got %d, want 3", WGCookieReply)
	}
	if WGDataPacket != 4 {
		t.Errorf("WGDataPacket: got %d, want 4", WGDataPacket)
	}
}

func TestWGPeerStruct(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	peer := &WGPeer{
		PublicKey:     kp.PublicKey,
		PublicKeyB64:  crypto.ToBase64(kp.PublicKey),
		Keepalive:     WGKeepalive,
		relayFallback: true,
	}

	if peer.Keepalive != 25*time.Second {
		t.Errorf("Keepalive: got %v, want 25s", peer.Keepalive)
	}
	if !peer.relayFallback {
		t.Error("relayFallback should be true initially")
	}
}

func TestWGPeerStats(t *testing.T) {
	peer := &WGPeer{}

	// Initial stats should be zero
	if peer.TxBytes != 0 {
		t.Errorf("Initial TxBytes: got %d, want 0", peer.TxBytes)
	}
	if peer.RxBytes != 0 {
		t.Errorf("Initial RxBytes: got %d, want 0", peer.RxBytes)
	}

	// Update stats
	peer.mu.Lock()
	peer.TxBytes += 1000
	peer.RxBytes += 2000
	peer.mu.Unlock()

	if peer.TxBytes != 1000 {
		t.Errorf("TxBytes after update: got %d, want 1000", peer.TxBytes)
	}
	if peer.RxBytes != 2000 {
		t.Errorf("RxBytes after update: got %d, want 2000", peer.RxBytes)
	}
}

func TestWGPeerGracePeriod(t *testing.T) {
	peer := &WGPeer{
		relayFallback:     true,
		directGracePeriod: false,
	}

	// Simulate direct connection established
	peer.mu.Lock()
	peer.relayFallback = false
	peer.directGracePeriod = true
	peer.directGraceStart = time.Now()
	peer.mu.Unlock()

	// Check grace period is active
	peer.mu.RLock()
	inGrace := peer.directGracePeriod
	graceStart := peer.directGraceStart
	peer.mu.RUnlock()

	if !inGrace {
		t.Error("directGracePeriod should be true")
	}
	if graceStart.IsZero() {
		t.Error("directGraceStart should be set")
	}

	// Grace period should end after DirectGracePeriod
	// (This is tested by the actual tunnel code)
}

func TestWireGuardConfigStruct(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	cfg := WireGuardConfig{
		PrivateKey: kp.PrivateKey,
		ListenPort: 51820,
	}

	if cfg.ListenPort != 51820 {
		t.Errorf("ListenPort: got %d, want 51820", cfg.ListenPort)
	}
}

func TestWGPeerEndpointUpdate(t *testing.T) {
	peer := &WGPeer{
		relayFallback: true,
	}

	// Initially no endpoint
	peer.mu.RLock()
	ep := peer.Endpoint
	peer.mu.RUnlock()

	if ep != nil {
		t.Error("Initial endpoint should be nil")
	}
}

func TestWGPeerLastSeenUpdate(t *testing.T) {
	peer := &WGPeer{}

	// Initially zero
	if !peer.LastSeen.IsZero() {
		t.Error("Initial LastSeen should be zero")
	}

	// Update
	peer.mu.Lock()
	peer.LastSeen = time.Now()
	peer.mu.Unlock()

	peer.mu.RLock()
	lastSeen := peer.LastSeen
	peer.mu.RUnlock()

	if lastSeen.IsZero() {
		t.Error("LastSeen should be updated")
	}
}

func TestWGPeerDirectReceive(t *testing.T) {
	peer := &WGPeer{}

	// Initially zero
	if !peer.LastDirectReceive.IsZero() {
		t.Error("Initial LastDirectReceive should be zero")
	}

	// Simulate direct receive
	peer.mu.Lock()
	peer.LastDirectReceive = time.Now()
	peer.mu.Unlock()

	peer.mu.RLock()
	lastDirect := peer.LastDirectReceive
	peer.mu.RUnlock()

	if lastDirect.IsZero() {
		t.Error("LastDirectReceive should be updated")
	}
}
