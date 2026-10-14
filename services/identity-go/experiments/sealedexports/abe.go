// Package sealedexports encrypts data exports so that only staff whose
// attributes satisfy the export's policy can open them, without a central
// service deciding at download time.
package sealedexports

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/abe/cpabe/tkn20"

	"tallowbrook.example/identity/experiments/accesspolicy"
)

// Authority holds the system keys. In the pilot it lives in the export
// worker; the master key is persisted with MarshalBinary to the worker's
// sealed volume.
type Authority struct {
	pp  tkn20.PublicKey
	msk tkn20.SystemSecretKey
}

// NewAuthority creates fresh system keys.
func NewAuthority() (*Authority, error) {
	pp, msk, err := tkn20.Setup(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authority{pp: pp, msk: msk}, nil
}

// Seal encrypts an export under policyText, e.g. "(dept: ops) and (region: eu)".
func (a *Authority) Seal(policyText string, export []byte) ([]byte, error) {
	toks, err := accesspolicy.Lex(policyText)
	if err != nil {
		return nil, err
	}
	var policy tkn20.Policy
	if err := policy.FromString(accesspolicy.Normalise(toks)); err != nil {
		return nil, fmt.Errorf("sealedexports: policy: %w", err)
	}
	return a.pp.Encrypt(rand.Reader, policy, export)
}

// StaffKey returns the key for a member of staff with the given attributes.
func (a *Authority) StaffKey(attrs map[string]string) ([]byte, error) {
	var at tkn20.Attributes
	at.FromMap(attrs)
	k, err := a.msk.KeyGen(rand.Reader, at)
	if err != nil {
		return nil, err
	}
	return k.MarshalBinary()
}
