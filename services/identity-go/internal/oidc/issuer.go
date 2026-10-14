package oidc

import (
	"crypto"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"tallowbrook.example/identity/internal/keyfile"
)

// IDTokenClaims are the claims of a customer-realm ID token.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce    string   `json:"nonce,omitempty"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr,omitempty"`
	SID      string   `json:"sid,omitempty"`
	Email    string   `json:"email,omitempty"`
	Verified bool     `json:"email_verified,omitempty"`
	TenantID string   `json:"tid,omitempty"`
}

// Issuer signs customer-realm ID tokens.
type Issuer struct {
	issuer string
	key    crypto.Signer
	ttl    time.Duration
	now    func() time.Time
}

// NewIssuer loads the signing key from keyFile.
func NewIssuer(issuer, keyFile string, ttl time.Duration) (*Issuer, error) {
	key, err := keyfile.Signer(keyFile)
	if err != nil {
		return nil, err
	}
	return &Issuer{issuer: issuer, key: key, ttl: ttl, now: time.Now}, nil
}

// Public returns the verification key published in the JWKS.
func (i *Issuer) Public() crypto.PublicKey { return i.key.Public() }

// TokenRequest carries what an ID token is about.
type TokenRequest struct {
	Subject   string
	ClientID  string
	Nonce     string
	SessionID string
	AuthTime  time.Time
	Methods   []string
	Email     string
	Verified  bool
	TenantID  string
}

func (i *Issuer) claims(req TokenRequest) IDTokenClaims {
	now := i.now()
	return IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   req.Subject,
			Audience:  jwt.ClaimStrings{req.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
		},
		Nonce:    req.Nonce,
		AuthTime: req.AuthTime.Unix(),
		AMR:      req.Methods,
		SID:      req.SessionID,
		Email:    req.Email,
		Verified: req.Verified,
		TenantID: req.TenantID,
	}
}

// IDToken signs an ID token for req.
func (i *Issuer) IDToken(req TokenRequest) (string, error) {
	tok := jwt.NewWithClaims(idTokenMethod, i.claims(req))
	tok.Header["kid"] = customerKeyID
	return tok.SignedString(i.key)
}
