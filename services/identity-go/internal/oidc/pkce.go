package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var (
	errChallengeMethod = errors.New("code_challenge_method not supported")
	errVerifierFormat  = errors.New("code_verifier is malformed")
	errVerifierMatch   = errors.New("code_verifier does not match")
)

// checkChallengeMethod accepts only the hashed method; "plain" is refused for
// every client.
func checkChallengeMethod(method string) error {
	if method != "S256" {
		return errChallengeMethod
	}
	return nil
}

// validVerifier applies RFC 7636 section 4.1: 43 to 128 unreserved characters.
func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_', r == '~':
		default:
			return false
		}
	}
	return true
}

// verifyPKCE checks a code_verifier against the challenge stored with the code.
func verifyPKCE(method, challenge, verifier string) error {
	if err := checkChallengeMethod(method); err != nil {
		return err
	}
	if !validVerifier(verifier) {
		return errVerifierFormat
	}
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		return errVerifierMatch
	}
	return nil
}
