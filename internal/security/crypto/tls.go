package crypto

import (
	"crypto/tls"
	"fmt"
)

// LoadServerTLSConfig loads a TLS 1.3-only server certificate and key pair.
func LoadServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS key pair: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// BuildClientTLSConfig builds a TLS 1.3-only client configuration.
func BuildClientTLSConfig(insecureSkipVerify bool) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // Explicitly configurable for self-signed pure-IP setups.
	}
}
