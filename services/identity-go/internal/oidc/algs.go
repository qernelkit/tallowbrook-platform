package oidc

import "github.com/golang-jwt/jwt/v5"

// Customer-realm ID tokens.
var idTokenMethod = jwt.SigningMethodES256

// Back-channel logout tokens.
const logoutTokenAlg = "EdDSA"

// Advertised in discovery: customer tokens, and workforce tokens signed in AWS.
var idTokenAlgValues = []string{"ES256", "ES384"}

// Key IDs published in the JWKS.
const (
	customerKeyID = "ts-es256-2026"
	logoutKeyID   = "ts-ed25519-2026"
)
