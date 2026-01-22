package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	KeySize = 32
)

type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// GenerateKeyPair creates a new X25519 key pair for WireGuard
func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [KeySize]byte
	var publicKey [KeySize]byte

	// Generate random private key
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Clamp private key for X25519
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// PrivateKeyFromBase64 decodes a base64-encoded private key
func PrivateKeyFromBase64(encoded string) ([KeySize]byte, error) {
	var key [KeySize]byte
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return key, fmt.Errorf("invalid base64: %w", err)
	}
	if len(decoded) != KeySize {
		return key, fmt.Errorf("invalid key size: expected %d, got %d", KeySize, len(decoded))
	}
	copy(key[:], decoded)
	return key, nil
}

// PublicKeyFromPrivate derives a public key from a private key
func PublicKeyFromPrivate(privateKey [KeySize]byte) [KeySize]byte {
	var publicKey [KeySize]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey
}

// ToBase64 encodes a key to base64
func ToBase64(key [KeySize]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// FromBase64 decodes a base64-encoded key
func FromBase64(encoded string) ([KeySize]byte, error) {
	var key [KeySize]byte
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return key, fmt.Errorf("invalid base64: %w", err)
	}
	if len(decoded) != KeySize {
		return key, fmt.Errorf("invalid key size: expected %d, got %d", KeySize, len(decoded))
	}
	copy(key[:], decoded)
	return key, nil
}

// SharedSecret computes a shared secret using X25519
func SharedSecret(privateKey, peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	var shared [KeySize]byte
	out, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return shared, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	copy(shared[:], out)
	return shared, nil
}

// GenerateNetworkSecret generates a random network secret
func GenerateNetworkSecret() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate network secret: %w", err)
	}
	return base64.URLEncoding.EncodeToString(secret), nil
}

// GenerateNetworkID generates a random network ID
func GenerateNetworkID() (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", fmt.Errorf("failed to generate network ID: %w", err)
	}
	return base64.URLEncoding.EncodeToString(id)[:22], nil
}
