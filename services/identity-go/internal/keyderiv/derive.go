// Package keyderiv expands a shared secret into keys bound to one purpose.
package keyderiv

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
)

// Derive returns length bytes bound to label. Cookie keys, signalling session
// keys and recovery bundle keys all come from here, so two features never end up
// with the same key even when they start from the same secret.
func Derive(secret, salt []byte, label string, length int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("keyderiv: empty secret")
	}
	if label == "" {
		return nil, errors.New("keyderiv: label is required")
	}
	if length <= 0 || length > 64 {
		return nil, errors.New("keyderiv: length out of range")
	}
	return hkdf.Key(sha256.New, secret, salt, label, length)
}
