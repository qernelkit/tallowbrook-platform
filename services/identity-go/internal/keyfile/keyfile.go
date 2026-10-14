// Package keyfile loads keys and certificates from PEM files on the host.
package keyfile

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func readBlock(path, wantType string) (*pem.Block, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("keyfile: %s: no PEM block", path)
	}
	if wantType != "" && block.Type != wantType {
		return nil, fmt.Errorf("keyfile: %s: found %q, want %q", path, block.Type, wantType)
	}
	return block, nil
}

// Signer reads an unencrypted PKCS #8 key and returns it as a crypto.Signer.
func Signer(path string) (crypto.Signer, error) {
	block, err := readBlock(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s: %w", path, err)
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("keyfile: %s: key cannot sign", path)
	}
	return s, nil
}

// Public reads a PKIX public key ("PUBLIC KEY" block).
func Public(path string) (any, error) {
	block, err := readBlock(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// Chain reads every certificate in a PEM file, leaf first.
func Chain(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("keyfile: %s: %w", path, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("keyfile: " + path + ": no certificates")
	}
	return out, nil
}

// Pool reads a PEM bundle into a certificate pool.
func Pool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("keyfile: %s: no certificates", path)
	}
	return pool, nil
}
