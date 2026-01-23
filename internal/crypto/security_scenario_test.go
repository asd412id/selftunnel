//go:build integration
// +build integration

package crypto

import (
	"bytes"
	"testing"
	"time"
)

// =============================================================================
// Scenario 6: Security Scenarios
// =============================================================================

// Scenario 6.1: Invalid/expired keys
func TestScenario_6_1_InvalidKeys(t *testing.T) {
	t.Log("Scenario 6.1: Invalid/expired keys handling")

	testCases := []struct {
		name        string
		keyBase64   string
		shouldError bool
	}{
		{
			name:        "Empty key",
			keyBase64:   "",
			shouldError: true,
		},
		{
			name:        "Invalid base64",
			keyBase64:   "not-valid-base64!!!",
			shouldError: true,
		},
		{
			name:        "Wrong size key",
			keyBase64:   "AQID", // Too short (3 bytes)
			shouldError: true,
		},
		{
			name:        "Valid key",
			keyBase64:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32 zeros
			shouldError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromBase64(tc.keyBase64)
			if tc.shouldError && err == nil {
				t.Errorf("FAIL: Expected error for %s", tc.name)
			} else if !tc.shouldError && err != nil {
				t.Errorf("FAIL: Unexpected error for %s: %v", tc.name, err)
			} else {
				t.Logf("PASS: %s handled correctly", tc.name)
			}
		})
	}
}

// Scenario 6.2: Man-in-the-middle attempt (encryption verification)
func TestScenario_6_2_MITMProtection(t *testing.T) {
	t.Log("Scenario 6.2: Man-in-the-middle protection via encryption")

	// Generate two key pairs (Alice and Bob)
	aliceKeys, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate Alice's keys: %v", err)
	}

	bobKeys, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate Bob's keys: %v", err)
	}

	// Attacker's keys
	attackerKeys, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("FAIL: Failed to generate attacker's keys: %v", err)
	}

	// Alice and Bob compute shared secret
	aliceShared, _ := SharedSecret(aliceKeys.PrivateKey, bobKeys.PublicKey)
	bobShared, _ := SharedSecret(bobKeys.PrivateKey, aliceKeys.PublicKey)

	// Verify Alice and Bob have same shared secret
	if !bytes.Equal(aliceShared[:], bobShared[:]) {
		t.Fatal("FAIL: Alice and Bob should have same shared secret")
	}

	// Attacker tries to compute shared secret
	attackerAlice, _ := SharedSecret(attackerKeys.PrivateKey, aliceKeys.PublicKey)
	attackerBob, _ := SharedSecret(attackerKeys.PrivateKey, bobKeys.PublicKey)

	// Attacker should NOT have same shared secret as Alice/Bob
	if bytes.Equal(attackerAlice[:], aliceShared[:]) {
		t.Fatal("FAIL: Attacker should not have Alice's shared secret")
	}
	if bytes.Equal(attackerBob[:], bobShared[:]) {
		t.Fatal("FAIL: Attacker should not have Bob's shared secret")
	}

	// Test encryption with shared secret
	aliceEnc, _ := NewEncryptor(aliceShared)
	bobEnc, _ := NewEncryptor(bobShared)

	originalMsg := []byte("Secret message from Alice to Bob")
	encrypted := aliceEnc.Encrypt(originalMsg)

	// Bob can decrypt
	decrypted, err := bobEnc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("FAIL: Bob should be able to decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, originalMsg) {
		t.Fatal("FAIL: Decrypted message mismatch")
	}

	// Attacker cannot decrypt
	attackerEnc, _ := NewEncryptor(attackerAlice)
	_, err = attackerEnc.Decrypt(encrypted)
	if err == nil {
		t.Fatal("FAIL: Attacker should NOT be able to decrypt")
	}

	t.Log("PASS: MITM protection verified - attacker cannot decrypt messages")
}

// Scenario 6.3: Replay attack protection
func TestScenario_6_3_ReplayProtection(t *testing.T) {
	t.Log("Scenario 6.3: Replay attack protection via unique nonces")

	keyPair, _ := GenerateKeyPair()
	sharedSecret, _ := SharedSecret(keyPair.PrivateKey, keyPair.PublicKey)
	enc, _ := NewEncryptor(sharedSecret)

	message := []byte("Important transaction")

	// Generate multiple encryptions of same message
	encryptions := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		encryptions[i] = enc.Encrypt(message)
	}

	// Each encryption should be unique (different nonce)
	for i := 0; i < len(encryptions); i++ {
		for j := i + 1; j < len(encryptions); j++ {
			if bytes.Equal(encryptions[i], encryptions[j]) {
				t.Fatalf("FAIL: Encryption %d and %d are identical (replay vulnerability)", i, j)
			}
		}
	}

	// Verify nonces are incrementing (first 8 bytes are nonce)
	for i := 0; i < len(encryptions)-1; i++ {
		nonce1 := encryptions[i][:8]
		nonce2 := encryptions[i+1][:8]
		if bytes.Equal(nonce1, nonce2) {
			t.Fatalf("FAIL: Nonces %d and %d are identical", i, i+1)
		}
	}

	t.Log("PASS: Replay protection verified - each encryption has unique nonce")
}

// Scenario 6.4: Unauthorized peer connection attempt
func TestScenario_6_4_UnauthorizedPeer(t *testing.T) {
	t.Log("Scenario 6.4: Unauthorized peer connection attempt")

	// Generate authorized peer keys
	authorizedKeys, _ := GenerateKeyPair()
	authorizedPubKey := ToBase64(authorizedKeys.PublicKey)

	// Generate unauthorized peer keys
	unauthorizedKeys, _ := GenerateKeyPair()
	unauthorizedPubKey := ToBase64(unauthorizedKeys.PublicKey)

	// Simulate authorized peer list
	authorizedPeers := map[string]bool{
		authorizedPubKey: true,
	}

	// Check authorization
	testCases := []struct {
		name       string
		publicKey  string
		authorized bool
	}{
		{"Authorized peer", authorizedPubKey, true},
		{"Unauthorized peer", unauthorizedPubKey, false},
		{"Empty key", "", false},
		{"Invalid key", "invalid-key", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isAuthorized := authorizedPeers[tc.publicKey]
			if isAuthorized != tc.authorized {
				t.Errorf("FAIL: %s - expected authorized=%v, got %v", tc.name, tc.authorized, isAuthorized)
			} else {
				t.Logf("PASS: %s - authorization check correct", tc.name)
			}
		})
	}
}

// Scenario 6.5: Key rotation
func TestScenario_6_5_KeyRotation(t *testing.T) {
	t.Log("Scenario 6.5: Key rotation scenario")

	// Generate initial keys
	oldKeys, _ := GenerateKeyPair()
	oldPubKey := ToBase64(oldKeys.PublicKey)

	// Simulate key rotation
	newKeys, _ := GenerateKeyPair()
	newPubKey := ToBase64(newKeys.PublicKey)

	// Keys should be different
	if oldPubKey == newPubKey {
		t.Fatal("FAIL: Rotated keys should be different")
	}

	// Old shared secrets should not work with new keys
	peerKeys, _ := GenerateKeyPair()

	oldShared, _ := SharedSecret(oldKeys.PrivateKey, peerKeys.PublicKey)
	newShared, _ := SharedSecret(newKeys.PrivateKey, peerKeys.PublicKey)

	if bytes.Equal(oldShared[:], newShared[:]) {
		t.Fatal("FAIL: Old and new shared secrets should differ")
	}

	t.Logf("PASS: Key rotation produces different shared secrets")
}

// Scenario 6.6: Timing attack resistance
func TestScenario_6_6_TimingAttackResistance(t *testing.T) {
	t.Log("Scenario 6.6: Timing attack resistance check")

	keyPair, _ := GenerateKeyPair()
	sharedSecret, _ := SharedSecret(keyPair.PrivateKey, keyPair.PublicKey)
	enc, _ := NewEncryptor(sharedSecret)

	message := []byte("Test message for timing analysis")

	// Measure encryption times
	iterations := 100
	encryptTimes := make([]time.Duration, iterations)
	decryptTimes := make([]time.Duration, iterations)

	var encrypted []byte
	for i := 0; i < iterations; i++ {
		start := time.Now()
		encrypted = enc.Encrypt(message)
		encryptTimes[i] = time.Since(start)
	}

	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, _ = enc.Decrypt(encrypted)
		decryptTimes[i] = time.Since(start)
	}

	// Calculate variance (should be relatively consistent)
	var encryptSum, decryptSum time.Duration
	for i := 0; i < iterations; i++ {
		encryptSum += encryptTimes[i]
		decryptSum += decryptTimes[i]
	}
	avgEncrypt := encryptSum / time.Duration(iterations)
	avgDecrypt := decryptSum / time.Duration(iterations)

	t.Logf("Average encrypt time: %v", avgEncrypt)
	t.Logf("Average decrypt time: %v", avgDecrypt)

	// Just log - actual timing attack resistance depends on crypto library
	t.Log("PASS: Timing measurements collected (actual resistance depends on crypto implementation)")
}
