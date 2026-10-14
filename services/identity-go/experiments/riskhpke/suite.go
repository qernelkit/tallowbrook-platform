// Package riskhpke seals sign-in risk signals for the fraud team's analysis
// service. Signals pass through the shared event bus, which the analysis
// service is the only reader able to open.
package riskhpke

import (
	"crypto/rand"
	"encoding/json"
	"time"

	"github.com/cloudflare/circl/hpke"
)

var riskSignalSuite = hpke.NewSuite(
	hpke.KEM_XWING,
	hpke.KDF_HKDF_SHA256,
	hpke.AEAD_AES256GCM)

const info = "tallowbrook risk signal v1"

// Signal is one sign-in risk observation.
type Signal struct {
	At        time.Time `json:"at"`
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	Method    string    `json:"method"`
	Outcome   string    `json:"outcome"`
	RiskScore float64   `json:"risk_score"`
}

// Sealed is a signal as published on the bus.
type Sealed struct {
	Enc  []byte `json:"enc"`
	Body []byte `json:"body"`
}

// ReceiverKeys creates a key pair for the analysis service. Its provisioning
// job runs this once and keeps the private half.
func ReceiverKeys() (pub, priv []byte, err error) {
	kemID, _, _ := riskSignalSuite.Params()
	pk, sk, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	if pub, err = pk.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	if priv, err = sk.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// Seal encrypts s to the analysis service's public key.
func Seal(receiver []byte, s Signal) (*Sealed, error) {
	kemID, _, _ := riskSignalSuite.Params()
	pk, err := kemID.Scheme().UnmarshalBinaryPublicKey(receiver)
	if err != nil {
		return nil, err
	}
	sender, err := riskSignalSuite.NewSender(pk, []byte(info))
	if err != nil {
		return nil, err
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	ct, err := sealer.Seal(body, nil)
	if err != nil {
		return nil, err
	}
	return &Sealed{Enc: enc, Body: ct}, nil
}
