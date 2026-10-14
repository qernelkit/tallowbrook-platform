package audit

import (
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// The compliance archive host countersigns every export it receives with the
// identity team's audit key. `idp admin audit-key` creates that key once; the
// private half goes to the archive host's HSM import, the public half into
// the archive's trust list.

const (
	auditKeyName  = "Tallowbrook Identity Audit"
	auditKeyEmail = "identity-audit@tallowbrook.example"
)

// NewSigningKey writes a new audit key pair, armoured, to priv and pub.
func NewSigningKey(priv, pub io.Writer) error {
	entity, err := pgp.NewEntity(auditKeyName, "", auditKeyEmail, nil)
	if err != nil {
		return err
	}
	pw, err := armor.Encode(priv, "PGP PRIVATE KEY BLOCK", nil)
	if err != nil {
		return err
	}
	if err := entity.SerializePrivateWithoutSigning(pw, nil); err != nil {
		return err
	}
	if err := pw.Close(); err != nil {
		return err
	}
	bw, err := armor.Encode(pub, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return err
	}
	if err := entity.Serialize(bw); err != nil {
		return err
	}
	return bw.Close()
}
