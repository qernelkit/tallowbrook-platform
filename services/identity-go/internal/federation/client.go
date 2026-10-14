// Package federation signs workforce users in through the corporate IdP.
package federation

import (
	"crypto/tls"
	"net/http"
	"time"

	"tallowbrook.example/identity/internal/keyfile"
)

// NewHTTPClient returns the client used for every call to the upstream IdP:
// discovery, its key set and the token endpoint. It trusts only the
// corporate root.
func NewHTTPClient(rootsFile string) (*http.Client, error) {
	roots, err := keyfile.Pool(rootsFile)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: roots},
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}, nil
}
