// Package testvectors provides a deterministic byte generator for golden
// tests: given the same seed it always produces the same bytes, so recorded
// fixtures stay stable across runs and machines.
//
// The generator is SP 800-90A CTR_DRBG with AES-256 and no derivation
// function. It is for fixtures only.
package testvectors

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	keyLen  = 32
	seedLen = 48 // key + one block
)

// CTRDRBG is a deterministic generator.
type CTRDRBG struct {
	key [keyLen]byte
	v   [16]byte
}

// NewCTRDRBG instantiates the generator from 48 bytes of seed material and an
// optional personalization string of at most 48 bytes.
func NewCTRDRBG(entropy, personalization []byte) (*CTRDRBG, error) {
	if len(entropy) != seedLen {
		return nil, errors.New("testvectors: seed must be 48 bytes")
	}
	if len(personalization) > seedLen {
		return nil, errors.New("testvectors: personalization longer than 48 bytes")
	}
	material := make([]byte, seedLen)
	copy(material, personalization)
	for i := range material {
		material[i] ^= entropy[i]
	}
	d := &CTRDRBG{}
	if err := d.update(material); err != nil {
		return nil, err
	}
	return d, nil
}

// keystream encrypts V+1, V+2, ... under the current key, returns n bytes of
// output and advances V past the blocks it used.
func (d *CTRDRBG) keystream(n int) ([]byte, error) {
	block, err := aes.NewCipher(d.key[:])
	if err != nil {
		return nil, err
	}
	ctr := d.v
	increment(ctr[:])
	stream := cipher.NewCTR(block, ctr[:])
	blocks := (n + 15) / 16
	out := make([]byte, blocks*16)
	stream.XORKeyStream(out, out)
	for i := 0; i < blocks; i++ {
		increment(d.v[:])
	}
	return out[:n], nil
}

// update is the CTR_DRBG_Update function of SP 800-90A section 10.2.1.2.
func (d *CTRDRBG) update(provided []byte) error {
	temp, err := d.keystream(seedLen)
	if err != nil {
		return err
	}
	for i := range provided {
		temp[i] ^= provided[i]
	}
	copy(d.key[:], temp[:keyLen])
	copy(d.v[:], temp[keyLen:])
	return nil
}

// Read fills p and then updates the state, as Generate does with no
// additional input.
func (d *CTRDRBG) Read(p []byte) (int, error) {
	out, err := d.keystream(len(p))
	if err != nil {
		return 0, err
	}
	copy(p, out)
	if err := d.update(nil); err != nil {
		return 0, err
	}
	return len(p), nil
}

func increment(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}
