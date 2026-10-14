// Package sealing protects small records (provisioning bundles, escrow blobs)
// under a 32-byte key. The nonce is generated per call and stored with the
// output, so callers only keep the key.
package sealing

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// ErrKeySize is returned for keys that are not exactly 32 bytes.
var ErrKeySize = errors.New("sealing: key must be 32 bytes")

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

// Seal protects plaintext and binds it to context, which must be passed again
// to Open.
func Seal(key, plaintext, context []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, plaintext, context), nil
}

// Open reverses Seal.
func Open(key, sealed, context []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, nil, sealed, context)
	if err != nil {
		return nil, errors.New("sealing: record does not open with this key")
	}
	return out, nil
}
