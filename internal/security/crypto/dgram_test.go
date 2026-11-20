package crypto

import (
	"bytes"
	"testing"
)

func TestDatagramCipherRoundTrip(t *testing.T) {
	c, err := NewDatagramCipher("shared-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range [][]byte{
		[]byte("hello"),
		[]byte(""),
		bytes.Repeat([]byte{0xAB}, 4096),
	} {
		sealed := c.Seal(plaintext)
		if bytes.Equal(sealed, plaintext) {
			t.Fatal("sealed payload must differ from plaintext")
		}
		got, err := c.Open(sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
		}
	}
}

func TestDatagramCipherFreshNonce(t *testing.T) {
	c, err := NewDatagramCipher("shared-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	a := c.Seal([]byte("same plaintext"))
	b := c.Seal([]byte("same plaintext"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext must differ (random nonce)")
	}
}

func TestDatagramCipherRejectsTamper(t *testing.T) {
	c, err := NewDatagramCipher("shared-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	sealed := c.Seal([]byte("authenticated payload"))
	sealed[len(sealed)-1] ^= 0xFF // 翻转认证标签的一个 bit
	if _, err := c.Open(sealed); err == nil {
		t.Fatal("tampered datagram must be rejected")
	}
	if _, err := c.Open([]byte("short")); err == nil {
		t.Fatal("short datagram must be rejected")
	}
}

func TestDatagramCipherWrongTokenFails(t *testing.T) {
	a, _ := NewDatagramCipher("token-a")
	b, _ := NewDatagramCipher("token-b")
	sealed := a.Seal([]byte("secret"))
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("wrong key must not decrypt")
	}
}

func TestNewDatagramCipherRejectsEmptyToken(t *testing.T) {
	if _, err := NewDatagramCipher(""); err == nil {
		t.Fatal("empty token must be rejected")
	}
}
