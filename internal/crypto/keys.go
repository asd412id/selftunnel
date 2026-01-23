package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
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

// Encryptor handles authenticated encryption using ChaCha20-Poly1305
type Encryptor struct {
	aead  cipher.AEAD
	nonce uint64 // atomic counter for nonce
}

// NewEncryptor creates a new encryptor from a shared secret
func NewEncryptor(sharedSecret [KeySize]byte) (*Encryptor, error) {
	aead, err := chacha20poly1305.New(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	return &Encryptor{aead: aead}, nil
}

// Encrypt encrypts plaintext with authentication
// Returns: nonce (8 bytes) + ciphertext + tag (16 bytes)
func (e *Encryptor) Encrypt(plaintext []byte) []byte {
	// Use atomic counter for nonce to ensure uniqueness
	nonceVal := atomic.AddUint64(&e.nonce, 1)

	// Build 12-byte nonce: 4 zero bytes + 8-byte counter
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], nonceVal)

	// Encrypt and authenticate
	// Output: 8-byte nonce counter + ciphertext + 16-byte tag
	result := make([]byte, 8, 8+len(plaintext)+chacha20poly1305.Overhead)
	binary.LittleEndian.PutUint64(result, nonceVal)

	return e.aead.Seal(result, nonce, plaintext, nil)
}

// Decrypt decrypts and authenticates ciphertext
// Input: nonce (8 bytes) + ciphertext + tag (16 bytes)
func (e *Encryptor) Decrypt(data []byte) ([]byte, error) {
	if len(data) < 8+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce counter from data
	nonceVal := binary.LittleEndian.Uint64(data[:8])

	// Build 12-byte nonce
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], nonceVal)

	// Decrypt and verify
	plaintext, err := e.aead.Open(nil, nonce, data[8:], nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
