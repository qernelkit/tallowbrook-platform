// Package recovery escrows account-recovery secrets for workforce accounts.
// When an employee loses every authenticator, the service desk opens the
// escrow record offline and walks them through re-enrolment.
//
// Version 1 records are wrapped to the service desk's public key. Version 2
// records use a fresh key per enrolment whose private half is wrapped by AWS,
// so opening one needs both the offline tool and an AWS grant.
package recovery

import (
	"context"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"tallowbrook.example/identity/internal/keyderiv"
	"tallowbrook.example/identity/internal/keyfile"
	"tallowbrook.example/identity/internal/sealing"
)

// WrapAPI is the part of the AWS client escrow v2 uses.
type WrapAPI interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
}

// Record is one escrowed secret.
type Record struct {
	UserID     string    `json:"user_id"`
	Version    int       `json:"version"`
	Created    time.Time `json:"created"`
	Wrapped    []byte    `json:"wrapped,omitempty"`     // v1
	KEMOutput  []byte    `json:"kem_output,omitempty"`  // v2
	Sealed     []byte    `json:"sealed,omitempty"`      // v2
	WrappedKey []byte    `json:"wrapped_key,omitempty"` // v2
}

// Escrow writes escrow records.
type Escrow struct {
	helpdeskKey *rsa.PublicKey
	kms         WrapAPI
	keyID       string
	version     int
	now         func() time.Time
}

// New loads the service desk key. version selects the format of new records.
func New(helpdeskKeyFile string, api WrapAPI, keyID string, version int) (*Escrow, error) {
	pub, err := keyfile.Public(helpdeskKeyFile)
	if err != nil {
		return nil, err
	}
	rk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("recovery: service desk key has the wrong type")
	}
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("recovery: unknown record version %d", version)
	}
	return &Escrow{helpdeskKey: rk, kms: api, keyID: keyID, version: version, now: time.Now}, nil
}

// NewSecret returns a fresh recovery secret.
func NewSecret() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

// Enroll escrows secret for userID.
func (e *Escrow) Enroll(ctx context.Context, userID string, secret []byte) (*Record, error) {
	if e.version == 1 {
		return e.enrollV1(userID, secret)
	}
	return e.enrollV2(ctx, userID, secret)
}

func (e *Escrow) enrollV1(userID string, secret []byte) (*Record, error) {
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, e.helpdeskKey, secret, []byte("recovery-escrow"))
	if err != nil {
		return nil, err
	}
	return &Record{UserID: userID, Version: 1, Created: e.now().UTC(), Wrapped: wrapped}, nil
}

func (e *Escrow) enrollV2(ctx context.Context, userID string, secret []byte) (*Record, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	shared, kemOut := dk.EncapsulationKey().Encapsulate()
	recordKey, err := keyderiv.Derive(shared, []byte(userID), "recovery escrow v2", 32)
	if err != nil {
		return nil, err
	}
	sealed, err := sealing.Seal(recordKey, secret, []byte(userID))
	if err != nil {
		return nil, err
	}
	out, err := e.kms.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(e.keyID),
		Plaintext: dk.Bytes(),
	})
	if err != nil {
		return nil, fmt.Errorf("recovery: wrap record key: %w", err)
	}
	return &Record{
		UserID:     userID,
		Version:    2,
		Created:    e.now().UTC(),
		KEMOutput:  kemOut,
		Sealed:     sealed,
		WrappedKey: out.CiphertextBlob,
	}, nil
}
