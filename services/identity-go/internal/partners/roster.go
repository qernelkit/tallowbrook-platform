package partners

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// File format ("HLR3"): a 4-byte magic, then records of
//
//	uint32 sequence | uint32 CRC-32C of body | 8-byte IV | uint16 length | body
//
// where body is the fixed-width record, encrypted in CBC mode with the key
// Harborline gave us at onboarding.

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var magic = []byte("HLR3")

type rawRecord struct {
	Seq  uint32
	CRC  uint32
	IV   []byte
	Body []byte
}

// RosterReader decodes roster files.
type RosterReader struct {
	key []byte
}

// NewRosterReader takes the 24-byte Harborline key.
func NewRosterReader(key []byte) (*RosterReader, error) {
	if len(key) != 24 {
		return nil, errors.New("partners: roster key must be 24 bytes")
	}
	return &RosterReader{key: key}, nil
}

// Read returns the drivers in a roster file.
func (p *RosterReader) Read(r io.Reader) ([]Driver, error) {
	br := bufio.NewReader(r)
	head := make([]byte, len(magic))
	if _, err := io.ReadFull(br, head); err != nil || !bytes.Equal(head, magic) {
		return nil, errors.New("partners: not a roster file")
	}
	var drivers []Driver
	for {
		rec, err := readRecord(br)
		if err == io.EOF {
			return drivers, nil
		}
		if err != nil {
			return nil, err
		}
		body, err := p.openRecord(rec)
		if err != nil {
			return nil, err
		}
		d, err := parseDriver(body)
		if err != nil {
			return nil, fmt.Errorf("roster record %d: %w", rec.Seq, err)
		}
		drivers = append(drivers, d)
	}
}

// openRecord checks one record's CRC and decrypts its body.
func (p *RosterReader) openRecord(rec rawRecord) ([]byte, error) {
	if crc32.Checksum(rec.Body, castagnoli) != rec.CRC {
		return nil, fmt.Errorf("roster record %d: checksum mismatch", rec.Seq)
	}
	block, err := des.NewTripleDESCipher(p.key)
	if err != nil {
		return nil, err
	}
	if len(rec.Body) == 0 || len(rec.Body)%block.BlockSize() != 0 || len(rec.IV) != block.BlockSize() {
		return nil, fmt.Errorf("roster record %d: bad length", rec.Seq)
	}
	mode := cipher.NewCBCDecrypter(block, rec.IV)
	out := make([]byte, len(rec.Body))
	mode.CryptBlocks(out, rec.Body)
	return unpad(out, block.BlockSize())
}

func unpad(b []byte, size int) ([]byte, error) {
	n := int(b[len(b)-1])
	if n == 0 || n > size || n > len(b) {
		return nil, errors.New("partners: bad padding")
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errors.New("partners: bad padding")
		}
	}
	return b[:len(b)-n], nil
}

func readRecord(r io.Reader) (rawRecord, error) {
	var hdr [18]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return rawRecord{}, errors.New("partners: truncated record header")
		}
		return rawRecord{}, err
	}
	rec := rawRecord{
		Seq: binary.BigEndian.Uint32(hdr[0:4]),
		CRC: binary.BigEndian.Uint32(hdr[4:8]),
		IV:  append([]byte(nil), hdr[8:16]...),
	}
	n := binary.BigEndian.Uint16(hdr[16:18])
	rec.Body = make([]byte, n)
	if _, err := io.ReadFull(r, rec.Body); err != nil {
		return rawRecord{}, fmt.Errorf("partners: record %d truncated", rec.Seq)
	}
	return rec, nil
}
