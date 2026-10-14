package audit

import (
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// Exporter writes audit segments for the compliance archive. Exports are
// encrypted to the archive team's keys, so the files can sit in the shared
// transfer bucket.
type Exporter struct {
	recipients pgp.EntityList
}

// NewExporter reads the recipients' armoured public keys.
func NewExporter(recipientsFile string) (*Exporter, error) {
	f, err := os.Open(recipientsFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	list, err := pgp.ReadArmoredKeyRing(f)
	if err != nil {
		return nil, fmt.Errorf("audit: recipients: %w", err)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("audit: %s holds no keys", recipientsFile)
	}
	return &Exporter{recipients: list}, nil
}

// Export copies segment to w as an armoured, encrypted message.
func (x *Exporter) Export(w io.Writer, segment io.Reader, name string) error {
	cfg := &packet.Config{
		DefaultCipher: packet.CipherAES256,
		AEADConfig:    &packet.AEADConfig{DefaultMode: packet.AEADModeOCB},
	}
	armored, err := armor.Encode(w, "PGP MESSAGE", nil)
	if err != nil {
		return err
	}
	pt, err := pgp.Encrypt(armored, x.recipients, nil, nil, &pgp.FileHints{FileName: name, IsUTF8: true}, cfg)
	if err != nil {
		return err
	}
	if _, err := io.Copy(pt, segment); err != nil {
		return err
	}
	if err := pt.Close(); err != nil {
		return err
	}
	return armored.Close()
}
