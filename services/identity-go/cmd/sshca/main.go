// Command sshca is the SSH certificate authority: the HTTP API that issues
// user certificates, the laptop enrolment listener, and the KRL push to the
// bastions. `sshca break-glass <principal> <ticket>` prints an emergency kit.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"tallowbrook.example/identity/internal/config"
	"tallowbrook.example/identity/internal/httpx"
	"tallowbrook.example/identity/internal/sshca"
)

const krlPath = "/var/lib/identity/krl/current.krl"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	ca, err := sshca.NewAuthority(cfg.SSHUserCAKey, cfg.SSHUserCAPassphrase)
	if err != nil {
		log.Error("CA key", "err", err)
		os.Exit(1)
	}
	if len(os.Args) == 4 && os.Args[1] == "break-glass" {
		if err := breakGlass(ca, os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := serve(cfg, ca, log); err != nil {
		log.Error("sshca stopped", "err", err)
		os.Exit(1)
	}
}

func breakGlass(ca *sshca.Authority, principal, ticket string) error {
	if !strings.HasPrefix(ticket, "INC-") {
		return errors.New("break-glass needs an incident ticket (INC-...)")
	}
	kit, err := ca.BreakGlass(principal, ticket, 4*time.Hour)
	if err != nil {
		return err
	}
	fmt.Printf("# break-glass kit for %s, valid until %s\n", principal, kit.ValidUntil.UTC().Format(time.RFC3339))
	os.Stdout.Write(kit.PrivateKey)
	os.Stdout.Write(kit.Certificate)
	return nil
}

func serve(cfg *config.Config, ca *sshca.Authority, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	api := &sshca.API{
		CA:       ca,
		Identity: &userinfo{endpoint: cfg.PublicIssuer + "/userinfo", client: &http.Client{Timeout: 5 * time.Second}},
		TTL:      cfg.UserCertTTL,
		Log:      log,
	}
	mux := http.NewServeMux()
	api.Routes(mux)

	enrol, err := sshca.NewEnrollServer(cfg.EnrollHostKey, cfg.SSHUserCAPub, newEnrolments(), log)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.EnrollAddr)
	if err != nil {
		return err
	}
	pusher := sshca.NewKRLPusher(cfg.KRLPushKey, cfg.KRLPushCert, cfg.BastionKnownHosts, cfg.Bastions, log)

	errc := make(chan error, 2)
	go func() { errc <- enrol.Serve(ctx, ln) }()
	go func() { errc <- httpx.Serve(ctx, httpx.NewServer(cfg.ListenAddr, httpx.Stack(log, mux)), false, log) }()
	go pushLoop(ctx, pusher, log)
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			stop()
			return err
		}
	}
	return nil
}

// pushLoop pushes the KRL whenever the revocation job replaces it.
func pushLoop(ctx context.Context, p *sshca.KRLPusher, log *slog.Logger) {
	var last time.Time
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if st, err := os.Stat(krlPath); err == nil && st.ModTime().After(last) {
			krl, err := os.ReadFile(krlPath)
			if err == nil {
				failed, err := p.Push(ctx, krl)
				if err == nil && len(failed) == 0 {
					last = st.ModTime()
				} else {
					log.Warn("KRL push incomplete; will retry", "failed", failed, "err", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// userinfo resolves workforce access tokens through the IdP.
type userinfo struct {
	endpoint string
	client   *http.Client
}

func (u *userinfo) Username(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo: %s", resp.Status)
	}
	var body struct {
		Email    string `json:"email"`
		TenantID string `json:"tid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	name, domain, ok := strings.Cut(body.Email, "@")
	if !ok || domain != "tallowbrook.example" || body.TenantID != "t_tallowbrook" {
		return "", errors.New("userinfo: not a workforce account")
	}
	return name, nil
}

// enrolments records laptop enrolments in memory and hands out one-time
// tokens for the MDM agent.
type enrolments struct {
	mu     sync.Mutex
	tokens map[string]string
}

func newEnrolments() *enrolments {
	return &enrolments{tokens: make(map[string]string)}
}

func (e *enrolments) Enroll(_ context.Context, user, serial string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t := rand.Text()
	e.tokens[t] = user + "/" + serial
	return t, nil
}
