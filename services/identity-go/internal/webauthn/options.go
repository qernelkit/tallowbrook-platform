// Package webauthn implements passkey registration and sign-in for customer
// accounts. Options are built by hand from the W3C Level 3 definitions; the
// browser side uses the JSON helpers (PublicKeyCredential.parse*OptionsFromJSON).
package webauthn

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

const ceremonyTimeout = 2 * time.Minute

type credParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type rpEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type credDescriptor struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

type authenticatorSelection struct {
	ResidentKey      string `json:"residentKey"`
	UserVerification string `json:"userVerification"`
}

// CreationOptions is PublicKeyCredentialCreationOptionsJSON.
type CreationOptions struct {
	Challenge              string                 `json:"challenge"`
	RP                     rpEntity               `json:"rp"`
	User                   userEntity             `json:"user"`
	PubKeyCredParams       []credParam            `json:"pubKeyCredParams"`
	Timeout                int64                  `json:"timeout"`
	ExcludeCredentials     []credDescriptor       `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection authenticatorSelection `json:"authenticatorSelection"`
	Attestation            string                 `json:"attestation"`
}

// RequestOptions is PublicKeyCredentialRequestOptionsJSON.
type RequestOptions struct {
	Challenge        string           `json:"challenge"`
	RPID             string           `json:"rpId"`
	Timeout          int64            `json:"timeout"`
	AllowCredentials []credDescriptor `json:"allowCredentials,omitempty"`
	UserVerification string           `json:"userVerification"`
}

// RelyingParty holds the RP identity shown to the authenticator.
type RelyingParty struct {
	ID     string // e.g. "tallowbrook.example"
	Name   string
	Origin string // e.g. "https://id.tallowbrook.example"
}

func newChallenge() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Registration builds creation options for a user adding a passkey.
// existing lists the user's current credential IDs so the authenticator does
// not register the same one twice.
func (rp RelyingParty) Registration(userHandle []byte, email, displayName string, existing []string) CreationOptions {
	opts := CreationOptions{
		Challenge: newChallenge(),
		RP:        rpEntity{ID: rp.ID, Name: rp.Name},
		User: userEntity{
			ID:          base64.RawURLEncoding.EncodeToString(userHandle),
			Name:        email,
			DisplayName: displayName,
		},
		PubKeyCredParams: []credParam{
			{Type: "public-key", Alg: -7},
			{Type: "public-key", Alg: -8},
			{Type: "public-key", Alg: -257},
		},
		Timeout: ceremonyTimeout.Milliseconds(),
		AuthenticatorSelection: authenticatorSelection{
			ResidentKey:      "required",
			UserVerification: "required",
		},
		Attestation: "none",
	}
	for _, id := range existing {
		opts.ExcludeCredentials = append(opts.ExcludeCredentials, credDescriptor{Type: "public-key", ID: id})
	}
	return opts
}

// SignIn builds request options. With no allowed credentials the browser
// offers every discoverable credential for the RP.
func (rp RelyingParty) SignIn(allowed []string) RequestOptions {
	opts := RequestOptions{
		Challenge:        newChallenge(),
		RPID:             rp.ID,
		Timeout:          ceremonyTimeout.Milliseconds(),
		UserVerification: "required",
	}
	for _, id := range allowed {
		opts.AllowCredentials = append(opts.AllowCredentials, credDescriptor{Type: "public-key", ID: id, Transports: []string{"internal", "hybrid"}})
	}
	return opts
}
