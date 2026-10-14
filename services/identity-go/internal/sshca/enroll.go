package sshca

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Laptops run `ssh enroll@enroll.tallowbrook.example enroll <serial>` with the
// user certificate they got at their first sign-in. The server records the
// laptop against the user and prints a one-time token that the MDM agent
// exchanges for a device certificate.

var serialPattern = regexp.MustCompile(`^[A-Z0-9]{8,20}$`)

// Enrollments records laptop enrolments.
type Enrollments interface {
	Enroll(ctx context.Context, user, serial string) (token string, err error)
}

// EnrollServer is the SSH listener for laptop enrolment.
type EnrollServer struct {
	cfg   *ssh.ServerConfig
	store Enrollments
	log   *slog.Logger
}

// NewEnrollServer accepts user certificates signed by the CA in caPubPath.
func NewEnrollServer(hostKeyPath, caPubPath string, store Enrollments, log *slog.Logger) (*EnrollServer, error) {
	hostRaw, err := os.ReadFile(hostKeyPath)
	if err != nil {
		return nil, err
	}
	hostSigner, err := ssh.ParsePrivateKey(hostRaw)
	if err != nil {
		return nil, fmt.Errorf("sshca: enrolment host key: %w", err)
	}
	caRaw, err := os.ReadFile(caPubPath)
	if err != nil {
		return nil, err
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caRaw)
	if err != nil {
		return nil, fmt.Errorf("sshca: CA public key: %w", err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caPub.Marshal())
		},
	}
	cfg := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: enrollKeyExchanges,
			Ciphers:      enrollCiphers,
			MACs:         []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM},
		},
		PublicKeyCallback: checker.Authenticate,
		MaxAuthTries:      2,
	}
	cfg.AddHostKey(hostSigner)
	return &EnrollServer{cfg: cfg, store: store, log: log}, nil
}

// Serve accepts connections until ctx is done.
func (s *EnrollServer) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, conn)
	}
}

func (s *EnrollServer) handle(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(2 * time.Minute))
	conn, chans, reqs, err := ssh.NewServerConn(nc, s.cfg)
	if err != nil {
		s.log.Info("enrol connection refused", "remote", nc.RemoteAddr().String(), "err", err)
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	user := conn.Permissions.Extensions["user"]
	if user == "" {
		user = conn.User()
	}
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			return
		}
		s.session(ctx, user, ch, chReqs)
	}
}

func (s *EnrollServer) session(ctx context.Context, user string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		_ = req.Reply(true, nil)
		status := s.exec(ctx, user, parseExec(req.Payload), ch)
		_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, byte(status)})
		return
	}
}

func (s *EnrollServer) exec(ctx context.Context, user, command string, out io.Writer) int {
	fields := strings.Fields(command)
	if len(fields) != 2 || fields[0] != "enroll" {
		fmt.Fprintln(out, "usage: enroll <serial>")
		return 2
	}
	serial := strings.ToUpper(fields[1])
	if !serialPattern.MatchString(serial) {
		fmt.Fprintln(out, "serial must be 8-20 letters and digits")
		return 2
	}
	token, err := s.store.Enroll(ctx, user, serial)
	if err != nil {
		s.log.Warn("enrolment failed", "user", user, "serial", serial, "err", err)
		fmt.Fprintln(out, "enrolment failed; contact the service desk")
		return 1
	}
	s.log.Info("laptop enrolled", "user", user, "serial", serial)
	fmt.Fprintln(out, token)
	return 0
}

// parseExec decodes the "exec" request payload (a string with a uint32 length).
func parseExec(p []byte) string {
	if len(p) < 4 {
		return ""
	}
	n := int(p[0])<<24 | int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	if n > len(p)-4 {
		return ""
	}
	return string(p[4 : 4+n])
}

// ErrUnknownLaptop is returned by Enrollments for serials not in the MDM inventory.
var ErrUnknownLaptop = errors.New("sshca: serial not in inventory")
