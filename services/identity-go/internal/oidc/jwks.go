package oidc

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/go-jose/go-jose/v4"
)

var publishedKeys = map[string]jose.SignatureAlgorithm{
	customerKeyID: jose.ES256,
	logoutKeyID:   jose.EdDSA,
}

// KeySet serves /jwks.json. The document is built once at start-up; key
// rotation is a deploy.
type KeySet struct {
	body []byte
	etag string
}

// NewKeySet publishes the public half of every key in publishedKeys. keys maps
// key IDs to the public keys of the running signers.
func NewKeySet(keys map[string]crypto.PublicKey) (*KeySet, error) {
	kids := make([]string, 0, len(publishedKeys))
	for kid := range publishedKeys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	var set jose.JSONWebKeySet
	for _, kid := range kids {
		alg := publishedKeys[kid]
		pub, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("oidc: no key loaded for kid %s", kid)
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{KeyID: kid, Key: pub, Algorithm: string(alg), Use: "sig"})
	}
	body, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}
	return &KeySet{body: body, etag: etagFor(body)}, nil
}

// NewKeySetFor publishes the keys of the running customer-realm signers.
func NewKeySetFor(i *Issuer, n *LogoutNotifier) (*KeySet, error) {
	return NewKeySet(map[string]crypto.PublicKey{
		customerKeyID: i.Public(),
		logoutKeyID:   n.Public(),
	})
}

func (k *KeySet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	serveCached(w, r, k.body, k.etag, "public, max-age=3600")
}
