package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

var (
	ErrInvalidSignature = errors.New("auth: invalid challenge signature")
	ErrExpiredChallenge = errors.New("auth: challenge timestamp outside allowed window")
	ErrInvalidClientID  = errors.New("auth: client_id must not be empty")
)

// DefaultMaxClockSkew is the maximum allowed difference between challenge and verification time.
const DefaultMaxClockSkew = 60 * time.Second

// GenerateNonce returns a cryptographically random 16-byte hex string.
func GenerateNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// SignChallenge computes HMAC-SHA256(token, clientID + "|" + nonce + "|" + timestamp).
func SignChallenge(token, clientID, nonce string, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(clientID))
	mac.Write([]byte("|"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("|"))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyChallenge validates the timestamp skew and constant-time HMAC signature.
func VerifyChallenge(token, clientID, nonce string, timestamp int64, signature string, maxSkew time.Duration) error {
	if clientID == "" {
		return ErrInvalidClientID
	}
	if maxSkew <= 0 {
		maxSkew = DefaultMaxClockSkew
	}
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Second > maxSkew {
		return ErrExpiredChallenge
	}

	got, err := hex.DecodeString(signature)
	if err != nil {
		return ErrInvalidSignature
	}
	expectedHex := SignChallenge(token, clientID, nonce, timestamp)
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return ErrInvalidSignature
	}
	if !hmac.Equal(got, expected) {
		return ErrInvalidSignature
	}
	return nil
}
