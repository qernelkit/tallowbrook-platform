package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
)

// Credential is a registered passkey. The key is kept in the parts COSE
// uses: the uncompressed point for EC2, x for OKP, n and e for RSA.
type Credential struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Alg       int    `json:"alg"`
	Point     []byte `json:"point,omitempty"`
	X         []byte `json:"x,omitempty"`
	N         []byte `json:"n,omitempty"`
	E         []byte `json:"e,omitempty"`
	RPIDHash  []byte `json:"rp_id_hash"`
	SignCount uint32 `json:"sign_count"`
}

// AssertionResponse is AuthenticatorAssertionResponseJSON.
type AssertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

type collectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

var (
	errMalformedAssertion = errors.New("webauthn: malformed assertion")
	errWrongCeremony      = errors.New("webauthn: wrong ceremony type")
	errChallenge          = errors.New("webauthn: challenge does not match")
	errOrigin             = errors.New("webauthn: origin not allowed")
	errRPID               = errors.New("webauthn: assertion is for another relying party")
	errUserVerification   = errors.New("webauthn: user verification required")
	errBadSignature       = errors.New("webauthn: assertion signature does not verify")
	errUnsupportedAlg     = errors.New("webauthn: unsupported credential algorithm")
	errCounter            = errors.New("webauthn: signature counter went backwards")
)

const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
)

// VerifyAssertion checks a sign-in assertion for cred and returns the new
// signature counter.
func (rp RelyingParty) VerifyAssertion(cred Credential, resp AssertionResponse, challenge string) (uint32, error) {
	var clientData collectedClientData
	clientDataJSON, err := base64.RawURLEncoding.DecodeString(resp.ClientDataJSON)
	clientDataHash := sha256.Sum256(clientDataJSON)
	if err != nil || json.Unmarshal(clientDataJSON, &clientData) != nil {
		return 0, errMalformedAssertion
	}
	switch {
	case clientData.Type != "webauthn.get":
		return 0, errWrongCeremony
	case clientData.Challenge != challenge:
		return 0, errChallenge
	case clientData.Origin != rp.Origin || clientData.CrossOrigin:
		return 0, errOrigin
	}
	authData, err := base64.RawURLEncoding.DecodeString(resp.AuthenticatorData)
	if err != nil || len(authData) < 37 {
		return 0, errMalformedAssertion
	}
	if !bytes.Equal(authData[:32], cred.RPIDHash) {
		return 0, errRPID
	}
	flags := authData[32]
	if flags&flagUserPresent == 0 || flags&flagUserVerified == 0 {
		return 0, errUserVerification
	}
	counter := binary.BigEndian.Uint32(authData[33:37])
	if counter != 0 && counter <= cred.SignCount {
		return 0, errCounter
	}
	sig, err := base64.RawURLEncoding.DecodeString(resp.Signature)
	if err != nil {
		return 0, errMalformedAssertion
	}
	signed := append(append([]byte(nil), authData...), clientDataHash[:]...)
	ok, err := checkSignature(cred, signed, sig)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errBadSignature
	}
	return counter, nil
}

func checkSignature(cred Credential, signed, sig []byte) (bool, error) {
	switch cred.Alg {
	case -7:
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), cred.Point)
		if err != nil {
			return false, err
		}
		d := sha256.Sum256(signed)
		return ecdsa.VerifyASN1(pub, d[:], sig), nil
	case -8:
		x := cred.X
		if len(x) != 32 {
			return false, errMalformedAssertion
		}
		return ed25519.Verify(ed25519.PublicKey(x), signed, sig), nil
	case -257:
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(cred.N), E: int(new(big.Int).SetBytes(cred.E).Int64())}
		d := sha256.Sum256(signed)
		err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig)
		return err == nil, nil
	default:
		return false, errUnsupportedAlg
	}
}
