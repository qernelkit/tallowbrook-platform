package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// UpstreamClaims are the claims we use from the corporate IdP's ID tokens.
type UpstreamClaims struct {
	jwt.RegisteredClaims
	Email      string   `json:"email"`
	Name       string   `json:"name"`
	EmployeeID string   `json:"employee_id"`
	Groups     []string `json:"groups"`
}

// Verifier checks ID tokens issued by the corporate IdP.
type Verifier struct {
	issuer   string
	audience string
	algs     []string
	client   *http.Client

	mu      sync.Mutex
	keys    map[string]any
	fetched time.Time
}

// NewVerifier accepts tokens signed with one of algs.
func NewVerifier(issuer, audience string, algs []string, client *http.Client) *Verifier {
	return &Verifier{issuer: issuer, audience: audience, algs: algs, client: client, keys: map[string]any{}}
}

// Verify parses and checks raw, and returns its claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (*UpstreamClaims, error) {
	claims := &UpstreamClaims{}
	_, err := jwt.ParseWithClaims(raw, claims,
		func(t *jwt.Token) (any, error) { return v.keyFor(ctx, t) },
		jwt.WithValidMethods(v.algs),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("federation: upstream token rejected: %w", err)
	}
	if claims.EmployeeID == "" {
		return nil, errors.New("federation: upstream token has no employee_id")
	}
	return claims, nil
}

func (v *Verifier) keyFor(ctx context.Context, t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	// Unknown key ID: the upstream may have rotated. Refetch at most once a minute.
	if time.Since(v.fetched) < time.Minute {
		return nil, fmt.Errorf("federation: unknown key id %q", kid)
	}
	if err := v.refreshLocked(ctx); err != nil {
		return nil, err
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("federation: unknown key id %q", kid)
}

func (v *Verifier) refreshLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.issuer+"/.well-known/keys", nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("federation: key set fetch: %s", resp.Status)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("federation: key set: %w", err)
	}
	keys := make(map[string]any, len(set.Keys))
	for _, k := range set.Keys {
		if k.Use == "sig" || k.Use == "" {
			keys[k.KeyID] = k.Key
		}
	}
	v.keys = keys
	v.fetched = time.Now()
	return nil
}
