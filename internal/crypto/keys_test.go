package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Check key sizes
	if len(kp.PrivateKey) != KeySize {
		t.Errorf("Private key wrong size: got %d, want %d", len(kp.PrivateKey), KeySize)
	}
	if len(kp.PublicKey) != KeySize {
		t.Errorf("Public key wrong size: got %d, want %d", len(kp.PublicKey), KeySize)
	}

	// Check keys are not zero
	zeroKey := [KeySize]byte{}
	if bytes.Equal(kp.PrivateKey[:], zeroKey[:]) {
		t.Error("Private key should not be all zeros")
	}
	if bytes.Equal(kp.PublicKey[:], zeroKey[:]) {
		t.Error("Public key should not be all zeros")
	}

	// Check that two generated key pairs are different
	kp2, _ := GenerateKeyPair()
	if bytes.Equal(kp.PrivateKey[:], kp2.PrivateKey[:]) {
		t.Error("Two generated private keys should be different")
	}
}

func TestPublicKeyFromPrivate(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Derive public key from private key
	derivedPublic := PublicKeyFromPrivate(kp.PrivateKey)

	// Should match the original public key
	if !bytes.Equal(derivedPublic[:], kp.PublicKey[:]) {
		t.Error("Derived public key should match original")
	}
}

func TestBase64Encoding(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Encode to base64
	encoded := ToBase64(kp.PublicKey)
	if encoded == "" {
		t.Error("Encoded key should not be empty")
	}

	// Decode from base64
	decoded, err := FromBase64(encoded)
	if err != nil {
		t.Fatalf("Failed to decode key: %v", err)
	}

	// Should match original
	if !bytes.Equal(decoded[:], kp.PublicKey[:]) {
		t.Error("Decoded key should match original")
	}
}

func TestFromBase64Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"invalid base64", "not-valid-base64!!!"},
		{"wrong size", "AAAA"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromBase64(tt.input)
			if err == nil {
				t.Error("Expected error for invalid input")
			}
		})
	}
}

func TestPrivateKeyFromBase64(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Encode private key
	encoded := ToBase64(kp.PrivateKey)

	// Decode it back
	decoded, err := PrivateKeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("Failed to decode private key: %v", err)
	}

	if !bytes.Equal(decoded[:], kp.PrivateKey[:]) {
		t.Error("Decoded private key should match original")
	}
}

func TestSharedSecret(t *testing.T) {
	// Generate two key pairs
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	// Compute shared secrets
	secret1, err := SharedSecret(kp1.PrivateKey, kp2.PublicKey)
	if err != nil {
		t.Fatalf("Failed to compute shared secret 1: %v", err)
	}

	secret2, err := SharedSecret(kp2.PrivateKey, kp1.PublicKey)
	if err != nil {
		t.Fatalf("Failed to compute shared secret 2: %v", err)
	}

	// Both should be the same (Diffie-Hellman property)
	if !bytes.Equal(secret1[:], secret2[:]) {
		t.Error("Shared secrets should be equal")
	}

	// Should not be zero
	zeroKey := [KeySize]byte{}
	if bytes.Equal(secret1[:], zeroKey[:]) {
		t.Error("Shared secret should not be all zeros")
	}
}

func TestEncryptor(t *testing.T) {
	// Generate shared secret
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	secret, _ := SharedSecret(kp1.PrivateKey, kp2.PublicKey)

	// Create encryptors for both sides
	enc1, err := NewEncryptor(secret)
	if err != nil {
		t.Fatalf("Failed to create encryptor 1: %v", err)
	}
	enc2, err := NewEncryptor(secret)
	if err != nil {
		t.Fatalf("Failed to create encryptor 2: %v", err)
	}

	// Test encryption/decryption
	plaintext := []byte("Hello, SelfTunnel!")
	ciphertext := enc1.Encrypt(plaintext)

	// Ciphertext should be different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should differ from plaintext")
	}

	// Decrypt
	decrypted, err := enc2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Should match original
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text mismatch: got %s, want %s", decrypted, plaintext)
	}
}

func TestEncryptorNonceUniqueness(t *testing.T) {
	kp, _ := GenerateKeyPair()
	secret, _ := SharedSecret(kp.PrivateKey, kp.PublicKey)
	enc, _ := NewEncryptor(secret)

	plaintext := []byte("test")

	// Encrypt same plaintext multiple times
	ct1 := enc.Encrypt(plaintext)
	ct2 := enc.Encrypt(plaintext)
	ct3 := enc.Encrypt(plaintext)

	// All ciphertexts should be different due to unique nonces
	if bytes.Equal(ct1, ct2) {
		t.Error("Ciphertexts should be different (nonce uniqueness)")
	}
	if bytes.Equal(ct2, ct3) {
		t.Error("Ciphertexts should be different (nonce uniqueness)")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	kp, _ := GenerateKeyPair()
	secret, _ := SharedSecret(kp.PrivateKey, kp.PublicKey)
	enc, _ := NewEncryptor(secret)

	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{1, 2, 3}},
		{"corrupted", make([]byte, 100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := enc.Decrypt(tt.data)
			if err == nil {
				t.Error("Expected error for invalid data")
			}
		})
	}
}

func TestGenerateNetworkSecret(t *testing.T) {
	secret1, err := GenerateNetworkSecret()
	if err != nil {
		t.Fatalf("Failed to generate network secret: %v", err)
	}
	if secret1 == "" {
		t.Error("Network secret should not be empty")
	}

	// Generate another and ensure they're different
	secret2, _ := GenerateNetworkSecret()
	if secret1 == secret2 {
		t.Error("Two network secrets should be different")
	}
}

func TestGenerateNetworkID(t *testing.T) {
	id1, err := GenerateNetworkID()
	if err != nil {
		t.Fatalf("Failed to generate network ID: %v", err)
	}
	if id1 == "" {
		t.Error("Network ID should not be empty")
	}
	if len(id1) != 22 {
		t.Errorf("Network ID wrong length: got %d, want 22", len(id1))
	}

	// Generate another and ensure they're different
	id2, _ := GenerateNetworkID()
	if id1 == id2 {
		t.Error("Two network IDs should be different")
	}
}
