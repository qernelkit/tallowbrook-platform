// Package release fetches the risk-rules bundle that drives step-up decisions
// at sign-in. The fraud team publishes it with `cosign sign-blob`; the IdP
// refuses any bundle whose signature does not check out.
package release

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const releaseSigningKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqSSfRpjwTiN5dXBQ4hk2Cs9X/Fvp
j7dxfiKmdpGj4ee7pruohZa4zRgTDJdKS7AJ25d8q7Cqy/dlcs//5CMZLw==
-----END PUBLIC KEY-----
`

const maxBundleSize = 4 << 20

// VerifyBundle checks sig (base64, as cosign writes it) over bundle.
func VerifyBundle(name string, bundle, sigB64 []byte) error {
	block, _ := pem.Decode([]byte(releaseSigningKey))
	if block == nil {
		return errors.New("release: embedded key is unreadable")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("release: embedded key has the wrong type")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		return fmt.Errorf("release bundle %s: unreadable signature file", name)
	}
	digest := sha256.Sum256(bundle)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("release bundle %s: signature does not match the release key", name)
	}
	return nil
}

// Fetcher downloads the current bundle.
type Fetcher struct {
	BaseURL string
	Client  *http.Client
}

func (f *Fetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release: %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBundleSize))
}

// Latest returns the newest bundle after checking its signature.
func (f *Fetcher) Latest(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	bundle, err := f.get(ctx, f.BaseURL+"/risk-rules/latest.tar.gz")
	if err != nil {
		return nil, err
	}
	sig, err := f.get(ctx, f.BaseURL+"/risk-rules/latest.tar.gz.sig")
	if err != nil {
		return nil, err
	}
	if err := VerifyBundle("latest", bundle, sig); err != nil {
		return nil, err
	}
	return bundle, nil
}
