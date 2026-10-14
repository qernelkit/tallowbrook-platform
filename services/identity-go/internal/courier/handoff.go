// Package courier creates parcel hand-off codes. When a courier hands a
// parcel to a depot locker or a neighbour, the recipient gets a short code;
// the courier app shows it only after it opens the sealed copy we send it.
package courier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/nacl/box"
)

// Handoff is one parcel hand-off.
type Handoff struct {
	ParcelID string
	Code     string
	Sealed   []byte
}

var errParcel = errors.New("courier: parcel id is required")

// newCode returns six decimal digits.
func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// New creates a hand-off code for parcelID and seals it to the courier app's
// public key.
func New(parcelID string, courierKey [32]byte) (*Handoff, error) {
	if parcelID == "" {
		return nil, errParcel
	}
	code, err := newCode()
	if err != nil {
		return nil, err
	}
	sealed, err := box.SealAnonymous(nil, []byte(code), &courierKey, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Handoff{ParcelID: parcelID, Code: code, Sealed: sealed}, nil
}
