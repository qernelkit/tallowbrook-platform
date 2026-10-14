// Package approvals collects officer approvals for tenant deletions and
// data-export releases. Five officers hold a share each; any three produce an
// approval that the release tool combines and checks against one public key.
package approvals

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"

	tssrsa "github.com/cloudflare/circl/tss/rsa"
)

const officers, quorum = 5, 3

// Ceremony is the output of key setup: one share per officer and the public key.
type Ceremony struct {
	Shares []tssrsa.KeyShare
	Public *rsa.PublicKey
}

// Setup runs the key ceremony. The shares are written to the officers'
// smart cards by the ceremony tool and never stored together.
func Setup() (*Ceremony, error) {
	key, err := tssrsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	shares, err := tssrsa.Deal(rand.Reader, officers, quorum, key, false)
	if err != nil {
		return nil, err
	}
	return &Ceremony{Shares: shares, Public: &key.PublicKey}, nil
}

// Approve produces one officer's share of the approval for an action.
func Approve(share tssrsa.KeyShare, pub *rsa.PublicKey, approval []byte) (tssrsa.SignShare, error) {
	if len(approval) == 0 {
		return tssrsa.SignShare{}, errors.New("approvals: empty approval text")
	}
	digest := sha256.Sum256(approval)
	padded, err := tssrsa.PadHash(tssrsa.PKCS1v15Padder{}, crypto.SHA256, pub, digest[:])
	if err != nil {
		return tssrsa.SignShare{}, err
	}
	return share.Sign(rand.Reader, pub, padded, false)
}

// Quorum reports how many officer shares an approval needs.
func Quorum() (needed, of int) { return quorum, officers }
