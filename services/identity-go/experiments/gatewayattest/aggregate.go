// Package gatewayattest checks the nightly attestation from depot gateways.
// Each gateway signs a statement about its firmware; the depot's
// coordinator combines the signatures into one, so a single check covers the
// whole depot.
package gatewayattest

import (
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/bls"
)

type gatewayKey = bls.PublicKey[bls.G1]

// Statement is what one gateway attests to.
type Statement struct {
	GatewayID string
	Firmware  string
	Night     string // YYYY-MM-DD
}

func (s Statement) bytes() []byte {
	return []byte(fmt.Sprintf("tallowbrook gateway attestation\n%s\n%s\n%s", s.GatewayID, s.Firmware, s.Night))
}

var errAttestation = errors.New("gatewayattest: combined attestation does not verify")

// Verify checks a depot's combined attestation. rawKeys[i] is the registered
// key of the gateway that made statements[i].
func Verify(rawKeys [][]byte, statements []Statement, sig []byte) error {
	if len(rawKeys) == 0 || len(rawKeys) != len(statements) {
		return errors.New("gatewayattest: one key per statement")
	}
	keys := make([]*gatewayKey, len(rawKeys))
	msgs := make([][]byte, len(statements))
	for i, raw := range rawKeys {
		k := new(gatewayKey)
		if err := k.UnmarshalBinary(raw); err != nil {
			return fmt.Errorf("gatewayattest: key %d: %w", i, err)
		}
		keys[i] = k
		msgs[i] = statements[i].bytes()
	}
	if !bls.VerifyAggregate(keys, msgs, sig) {
		return errAttestation
	}
	return nil
}
