package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

const (
	nonceSize = 12 // AES-GCM 标准 nonce 长度
	keyTag    = "iplink/udp-v1/"
)

var (
	ErrCiphertextTooShort = errors.New("dgram: ciphertext shorter than nonce")
	ErrDecrypt            = errors.New("dgram: failed to decrypt datagram")
)

// DatagramCipher encrypts independent UDP datagrams with AES-256-GCM using a key
// derived from the shared token. Each datagram carries its own random nonce,
// so the cipher is stateless and safe for unordered/lossy UDP delivery.
type DatagramCipher struct {
	aead cipher.AEAD
}

// NewDatagramCipher derives a datagram cipher from token. An empty token is
// rejected so a misconfigured client cannot silently run unencrypted.
func NewDatagramCipher(token string) (*DatagramCipher, error) {
	if token == "" {
		return nil, errors.New("dgram: token must not be empty")
	}
	sum := sha256.Sum256([]byte(keyTag + token))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("dgram: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("dgram: create GCM: %w", err)
	}
	return &DatagramCipher{aead: aead}, nil
}

// Seal encrypts plaintext into [nonce][ciphertext+tag].
func (c *DatagramCipher) Seal(plaintext []byte) []byte {
	out := make([]byte, nonceSize, nonceSize+len(plaintext)+c.aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, out[:nonceSize]); err != nil {
		panic("dgram: crypto/rand failed: " + err.Error())
	}
	return c.aead.Seal(out, out[:nonceSize], plaintext, nil)
}

// Open decrypts a [nonce][ciphertext+tag] datagram produced by Seal.
func (c *DatagramCipher) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < nonceSize+c.aead.Overhead() {
		return nil, ErrCiphertextTooShort
	}
	plaintext, err := c.aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
