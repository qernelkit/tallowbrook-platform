// Package logintokens issues anonymous sign-in tokens to the courier app: the
// app proves it was enrolled without the depot gateway learning which
// handset it is. The app blinds a token, we sign it after checking the
// handset's enrolment, and the gateway later checks the unblinded signature.
package logintokens

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const loginTokenVariant = blindrsa.SHA384PSSDeterministic

// Issuer signs blinded tokens and checks redeemed ones.
type Issuer struct {
	signer   blindrsa.Signer
	verifier blindrsa.Verifier
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("logintokens: issuer key file is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("logintokens: issuer key has the wrong type")
	}
	return rk, nil
}

// NewIssuer loads the issuer key from keyPath.
func NewIssuer(keyPath string) (*Issuer, error) {
	issuerKey, err := loadKey(keyPath)
	if err != nil {
		return nil, err
	}
	signer := blindrsa.NewSigner(issuerKey)
	verifier, err := blindrsa.NewVerifier(loginTokenVariant, &issuerKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Issuer{signer: signer, verifier: verifier}, nil
}

// Sign signs a blinded token message.
func (i *Issuer) Sign(blinded []byte) ([]byte, error) {
	return i.signer.BlindSign(blinded)
}

// Redeem checks an unblinded token and its signature.
func (i *Issuer) Redeem(token, sig []byte) error {
	if len(token) != 32 {
		return errors.New("logintokens: token must be 32 bytes")
	}
	return i.verifier.Verify(token, sig)
}
