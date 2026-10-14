package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// BreakGlassKit is handed to the on-call engineer in a sealed envelope
// printout when SSO is down: a fresh key and a certificate valid for a few hours.
type BreakGlassKit struct {
	PrivateKey  []byte
	Certificate []byte
	ValidUntil  time.Time
}

// BreakGlass mints a key for principal and certifies it.
func (c *Authority) BreakGlass(principal, ticket string, ttl time.Duration) (*BreakGlassKit, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	cert, err := c.IssueUser(sshPub, CertRequest{
		KeyID:      fmt.Sprintf("break-glass %s %s", principal, ticket),
		Principals: []string{principal},
		TTL:        ttl,
	})
	if err != nil {
		return nil, err
	}
	return &BreakGlassKit{
		PrivateKey:  pem.EncodeToMemory(block),
		Certificate: ssh.MarshalAuthorizedKey(cert),
		ValidUntil:  time.Unix(int64(cert.ValidBefore), 0),
	}, nil
}
