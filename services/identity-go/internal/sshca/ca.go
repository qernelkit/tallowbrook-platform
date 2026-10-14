// Package sshca is the SSH certificate authority for workforce access to
// bastions: short-lived user certificates, laptop enrolment, break-glass keys
// and KRL distribution.
package sshca

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxUserCertTTL = 24 * time.Hour

var principalPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,31}$`)

// Authority signs user certificates.
type Authority struct {
	signer ssh.Signer
	serial atomic.Uint64
	now    func() time.Time
}

// NewAuthority loads the CA key. The key file is passphrase-protected; the
// passphrase is injected by the host's secret agent at start-up.
func NewAuthority(keyPath, passphrase string) (*Authority, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKeyWithPassphrase(raw, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("sshca: CA key: %w", err)
	}
	c := &Authority{signer: signer, now: time.Now}
	c.serial.Store(uint64(time.Now().UnixNano()))
	return c, nil
}

// CertRequest is a request for a user certificate.
type CertRequest struct {
	KeyID      string
	Principals []string
	TTL        time.Duration
	Extensions map[string]string
}

func (r CertRequest) validate() error {
	if r.KeyID == "" || len(r.Principals) == 0 {
		return errors.New("sshca: key id and principals are required")
	}
	for _, p := range r.Principals {
		if !principalPattern.MatchString(p) {
			return fmt.Errorf("sshca: bad principal %q", p)
		}
	}
	if r.TTL <= 0 || r.TTL > maxUserCertTTL {
		return fmt.Errorf("sshca: validity must be between 1s and %s", maxUserCertTTL)
	}
	return nil
}

// IssueUser signs a user certificate for pub.
func (c *Authority) IssueUser(pub ssh.PublicKey, req CertRequest) (*ssh.Certificate, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	ext := map[string]string{"permit-pty": ""}
	for k, v := range req.Extensions {
		ext[k] = v
	}
	now := c.now()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          c.serial.Add(1),
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(now.Add(-2 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(req.TTL).Unix()),
		Permissions:     ssh.Permissions{Extensions: ext},
	}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, err
	}
	return cert, nil
}
