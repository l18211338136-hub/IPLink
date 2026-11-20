package service

import (
	"testing"
	"time"
)

func TestPongStale(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	window := heartbeatInterval * missedPongLimit

	tests := []struct {
		name string
		last int64
		want bool
	}{
		{"no pong yet", 0, false},
		{"fresh pong", now.Add(-time.Second).UnixNano(), false},
		{"just within window", now.Add(-window + time.Second).UnixNano(), false},
		{"beyond window", now.Add(-window - time.Second).UnixNano(), true},
		{"ancient pong", now.Add(-24 * time.Hour).UnixNano(), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pongStale(tc.last, now); got != tc.want {
				t.Fatalf("pongStale(%d) = %v, want %v", tc.last, got, tc.want)
			}
		})
	}
}
