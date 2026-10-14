package sshca

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// The revocation job writes a KRL with `ssh-keygen -k` whenever a laptop or
// user is deprovisioned. KRLPusher copies it to every bastion, where a forced
// command installs it as RevokedKeys.

// KRLPusher pushes the current KRL to the bastions.
type KRLPusher struct {
	keyPath    string
	certPath   string
	knownHosts string
	bastions   []string
	log        *slog.Logger
}

func NewKRLPusher(keyPath, certPath, knownHosts string, bastions []string, log *slog.Logger) *KRLPusher {
	return &KRLPusher{keyPath: keyPath, certPath: certPath, knownHosts: knownHosts, bastions: bastions, log: log}
}

func (p *KRLPusher) clientSigner() (ssh.Signer, error) {
	keyRaw, err := os.ReadFile(p.keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(keyRaw)
	if err != nil {
		return nil, err
	}
	certRaw, err := os.ReadFile(p.certPath)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certRaw)
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("sshca: push certificate file holds a plain key")
	}
	return ssh.NewCertSigner(cert, signer)
}

// Push sends krl to every bastion and returns the hosts that failed.
func (p *KRLPusher) Push(ctx context.Context, krl []byte) ([]string, error) {
	signer, err := p.clientSigner()
	if err != nil {
		return nil, err
	}
	hostKeys, err := knownhosts.New(p.knownHosts)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            "krl-push",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeys,
		Timeout:         10 * time.Second,
	}
	var failed []string
	for _, addr := range p.bastions {
		if ctx.Err() != nil {
			return failed, ctx.Err()
		}
		if err := pushOne(addr, cfg, krl); err != nil {
			p.log.Warn("KRL push failed", "bastion", addr, "err", err)
			failed = append(failed, addr)
			continue
		}
		p.log.Info("KRL pushed", "bastion", addr, "bytes", len(krl))
	}
	return failed, nil
}

func pushOne(addr string, cfg *ssh.ClientConfig, krl []byte) error {
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader(krl)
	if out, err := sess.CombinedOutput("install-krl"); err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
