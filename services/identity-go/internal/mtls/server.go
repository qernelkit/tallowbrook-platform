// Package mtls runs the token endpoint with RFC 8705 client certificates.
// Confidential clients authenticate with a certificate from the issuing CA;
// public clients connect without one and rely on PKCE.
package mtls

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"tallowbrook.example/identity/internal/keyfile"
)

// NewServer returns the token endpoint server. Start it with
// ListenAndServeTLS("", "").
func NewServer(addr, certFile, keyFile, clientCAFile string, handler http.Handler) (*http.Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	clientCAs, err := keyfile.Pool(clientCAFile)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates:     []tls.Certificate{cert},
			ClientAuth:       tls.VerifyClientCertIfGiven,
			ClientCAs:        clientCAs,
			MinVersion:       tls.VersionTLS12,
			CipherSuites:     tokenEndpointSuites,
			CurvePreferences: tokenEndpointGroups,
		},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}, nil
}

// ClientID returns the client ID carried in the verified client certificate:
// the first DNS name under clients.tallowbrook.example.
func ClientID(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return "", false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	for _, name := range leaf.DNSNames {
		if id, ok := strings.CutSuffix(name, ".clients.tallowbrook.example"); ok && id != "" {
			return id, true
		}
	}
	return "", false
}
