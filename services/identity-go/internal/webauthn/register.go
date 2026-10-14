package webauthn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

// RegistrationResponse is the subset of RegistrationResponseJSON we read. With
// attestation "none" the browser's parsed fields are all we need.
type RegistrationResponse struct {
	ID       string `json:"id"`
	Response struct {
		ClientDataJSON     string   `json:"clientDataJSON"`
		AuthenticatorData  string   `json:"authenticatorData"`
		PublicKey          string   `json:"publicKey"`
		PublicKeyAlgorithm int      `json:"publicKeyAlgorithm"`
		Transports         []string `json:"transports"`
	} `json:"response"`
}

var errMalformedRegistration = errors.New("webauthn: malformed registration")

// FinishRegistration checks the browser's response and returns the credential
// to store. The RP ID hash the authenticator reports here is kept, and every
// later assertion is checked against it.
func (rp RelyingParty) FinishRegistration(userID string, reg RegistrationResponse, challenge string) (Credential, error) {
	cdj, err := base64.RawURLEncoding.DecodeString(reg.Response.ClientDataJSON)
	if err != nil {
		return Credential{}, errMalformedRegistration
	}
	var cd collectedClientData
	if err := json.Unmarshal(cdj, &cd); err != nil {
		return Credential{}, errMalformedRegistration
	}
	if cd.Type != "webauthn.create" {
		return Credential{}, errWrongCeremony
	}
	if cd.Challenge != challenge {
		return Credential{}, errChallenge
	}
	if cd.Origin != rp.Origin || cd.CrossOrigin {
		return Credential{}, errOrigin
	}
	authData, err := base64.RawURLEncoding.DecodeString(reg.Response.AuthenticatorData)
	if err != nil || len(authData) < 37 {
		return Credential{}, errMalformedRegistration
	}
	if authData[32]&flagUserVerified == 0 {
		return Credential{}, errUserVerification
	}
	spki, err := base64.RawURLEncoding.DecodeString(reg.Response.PublicKey)
	if err != nil {
		return Credential{}, errMalformedRegistration
	}
	cred := Credential{
		ID:       reg.ID,
		UserID:   userID,
		Alg:      reg.Response.PublicKeyAlgorithm,
		RPIDHash: append([]byte(nil), authData[:32]...),
	}
	if err := splitKey(&cred, spki); err != nil {
		return Credential{}, err
	}
	return cred, nil
}

// splitKey stores the parts of the SubjectPublicKeyInfo that sign-in needs.
func splitKey(cred *Credential, spki []byte) error {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return errMalformedRegistration
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		point, err := k.Bytes()
		if err != nil {
			return errMalformedRegistration
		}
		cred.Point = point
	case ed25519.PublicKey:
		cred.X = []byte(k)
	case *rsa.PublicKey:
		cred.N = k.N.Bytes()
		cred.E = big.NewInt(int64(k.E)).Bytes()
	default:
		return errUnsupportedAlg
	}
	return nil
}
