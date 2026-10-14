package oidc

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"tallowbrook.example/identity/internal/keyfile"
)

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutNotifier sends OpenID Connect back-channel logout tokens to relying
// parties when a session ends.
type LogoutNotifier struct {
	issuer string
	method jwt.SigningMethod
	key    crypto.Signer
	client *http.Client
	log    *slog.Logger
	now    func() time.Time
}

// NewLogoutNotifier loads the logout token key.
func NewLogoutNotifier(issuer, keyFile string, log *slog.Logger) (*LogoutNotifier, error) {
	key, err := keyfile.Signer(keyFile)
	if err != nil {
		return nil, err
	}
	method := jwt.GetSigningMethod(logoutTokenAlg)
	if method == nil {
		return nil, errors.New("oidc: logout signing method not registered")
	}
	return &LogoutNotifier{
		issuer: issuer,
		method: method,
		key:    key,
		client: &http.Client{Timeout: 5 * time.Second},
		log:    log,
		now:    time.Now,
	}, nil
}

// Public returns the verification key published in the JWKS.
func (n *LogoutNotifier) Public() crypto.PublicKey { return n.key.Public() }

func (n *LogoutNotifier) token(sub, sid, aud string) (string, error) {
	now := n.now()
	tok := jwt.NewWithClaims(n.method, jwt.MapClaims{
		"iss":    n.issuer,
		"sub":    sub,
		"aud":    aud,
		"iat":    now.Unix(),
		"exp":    now.Add(2 * time.Minute).Unix(),
		"jti":    fmt.Sprintf("%s.%d", sid, now.UnixNano()),
		"sid":    sid,
		"events": map[string]any{logoutEvent: map[string]any{}},
	})
	tok.Header["typ"] = "logout+jwt"
	tok.Header["kid"] = logoutKeyID
	return tok.SignedString(n.key)
}

// Notify tells each client that the session sid of user sub has ended.
// Failures are logged; a relying party that misses a logout still expires the
// session on its own schedule.
func (n *LogoutNotifier) Notify(ctx context.Context, clients []*Client, sub, sid string) {
	for _, c := range clients {
		t, err := n.token(sub, sid, c.ID)
		if err != nil {
			n.log.Error("logout token", "client", c.ID, "err", err)
			continue
		}
		form := url.Values{"logout_token": {t}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BackchannelLogoutURI, bytes.NewBufferString(form.Encode()))
		if err != nil {
			n.log.Error("logout request", "client", c.ID, "err", err)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := n.client.Do(req)
		if err != nil {
			n.log.Warn("logout delivery failed", "client", c.ID, "err", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			n.log.Warn("logout rejected", "client", c.ID, "status", resp.StatusCode)
		}
	}
}
