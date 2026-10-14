package oidc

import (
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/go-jose/go-jose/v4"

	"tallowbrook.example/identity/internal/keyfile"
)

// tokenWrapper encrypts signed ID tokens for the relying parties listed in
// encryptedClients. Their public keys are loaded once.
type tokenWrapper struct {
	mu   sync.Mutex
	keys map[string]*rsa.PublicKey
}

func newTokenWrapper() *tokenWrapper {
	return &tokenWrapper{keys: make(map[string]*rsa.PublicKey)}
}

func (w *tokenWrapper) rpKey(clientID string, ce clientEncryption) (*rsa.PublicKey, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if k, ok := w.keys[clientID]; ok {
		return k, nil
	}
	pub, err := keyfile.Public(ce.KeyFile)
	if err != nil {
		return nil, err
	}
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("oidc: %s: registered key has the wrong type", clientID)
	}
	w.keys[clientID] = k
	return k, nil
}

// wrap returns signed unchanged for ordinary clients, and as a compact JWE
// for clients that registered for encrypted tokens.
func (w *tokenWrapper) wrap(clientID, signed string) (string, error) {
	ce, ok := encryptedClients[clientID]
	if !ok {
		return signed, nil
	}
	rpKey, err := w.rpKey(clientID, ce)
	if err != nil {
		return "", err
	}
	enc, err := jose.NewEncrypter(
		ce.ContentEnc,
		jose.Recipient{Algorithm: ce.KeyAlg, Key: rpKey},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		return "", err
	}
	obj, err := enc.Encrypt([]byte(signed))
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}
