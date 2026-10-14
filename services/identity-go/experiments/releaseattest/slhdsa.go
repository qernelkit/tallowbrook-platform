// Package releaseattest creates the key that signs build attestations for
// identity releases. The attestations are long-lived records, so the key uses
// a hash-based scheme.
package releaseattest

import (
	"github.com/cloudflare/circl/sign/slhdsa"
)

const attestationParams = slhdsa.SHA2_128s

// NewKey returns a fresh key pair, serialized.
func NewKey() (pubBytes, privBytes []byte, err error) {
	pub, priv, err := attestationParams.Scheme().GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	if pubBytes, err = pub.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	if privBytes, err = priv.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	return pubBytes, privBytes, nil
}
