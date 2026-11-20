package auth

import (
	"errors"
	"testing"
	"time"
)

func TestChallengeSignAndVerify(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	ts := time.Now().Unix()
	token := "super-secret-token"
	sig := SignChallenge(token, "client-001", nonce, ts)

	if err := VerifyChallenge(token, "client-001", nonce, ts, sig, DefaultMaxClockSkew); err != nil {
		t.Fatalf("VerifyChallenge valid failed: %v", err)
	}
	if err := VerifyChallenge("wrong-token", "client-001", nonce, ts, sig, DefaultMaxClockSkew); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	if err := VerifyChallenge(token, "client-001", nonce, ts-3600, sig, DefaultMaxClockSkew); !errors.Is(err, ErrExpiredChallenge) {
		t.Fatalf("expected ErrExpiredChallenge, got %v", err)
	}
}
