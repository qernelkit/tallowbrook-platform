// Command idp is Tallowbrook's identity provider: the OpenID Connect issuer,
// customer and workforce sign-in, sessions, and the internal endpoints that
// device management and the courier platform call.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"tallowbrook.example/identity/internal/audit"
	"tallowbrook.example/identity/internal/avatars"
	"tallowbrook.example/identity/internal/config"
	"tallowbrook.example/identity/internal/ctwatch"
	"tallowbrook.example/identity/internal/devicecerts"
	"tallowbrook.example/identity/internal/federation"
	"tallowbrook.example/identity/internal/httpx"
	"tallowbrook.example/identity/internal/keyderiv"
	"tallowbrook.example/identity/internal/magiclink"
	"tallowbrook.example/identity/internal/mtls"
	"tallowbrook.example/identity/internal/notify"
	"tallowbrook.example/identity/internal/oidc"
	"tallowbrook.example/identity/internal/provisioning"
	"tallowbrook.example/identity/internal/recovery"
	"tallowbrook.example/identity/internal/release"
	"tallowbrook.example/identity/internal/scim"
	"tallowbrook.example/identity/internal/session"
	"tallowbrook.example/identity/internal/tenants"
	"tallowbrook.example/identity/internal/tokenize"
	"tallowbrook.example/identity/internal/users"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		os.Exit(admin(os.Args[2:]))
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("idp stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.CookieSecret == "" {
		return errors.New("IDP_COOKIE_SECRET is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}
	awsKeys := kms.NewFromConfig(awsCfg)

	// Sessions.
	sessions, err := session.NewStore(ctx, awsKeys, cfg.SessionKeyARN, cfg.SessionShards, cfg.SessionTTL)
	if err != nil {
		return err
	}
	cookieKey, err := keyderiv.Derive([]byte(cfg.CookieSecret), nil, "session cookie v1", 32)
	if err != nil {
		return err
	}
	cookies, err := session.NewCookieCodec(cookieKey, true)
	if err != nil {
		return err
	}
	markKey, err := keyderiv.Derive([]byte(cfg.CookieSecret), nil, "device mark v1", 32)
	if err != nil {
		return err
	}
	devices, err := session.NewDeviceMarker(markKey)
	if err != nil {
		return err
	}
	refresh := session.NewRefreshStore(cfg.RefreshTTL)

	// Accounts and tenants.
	userStore := users.NewStore()
	tenantStore := tenants.NewStore()
	relay := notify.NewRelayClient(cfg.RelayAddr, []byte(cfg.RelaySecret))
	links := magiclink.New(awsKeys, cfg.MagicLinkKeyID, cfg.PublicIssuer, cfg.MagicLinkTTL)
	accounts := &users.Service{
		Store:      userStore,
		Sessions:   sessions,
		Cookies:    cookies,
		Links:      links,
		Devices:    devices,
		Mail:       relay,
		SessionTTL: cfg.SessionTTL,
		Limiter:    httpx.NewRateLimiter(30, 10),
		Log:        log,
		Now:        time.Now,
	}

	// OpenID Connect.
	provider, err := newProvider(cfg, log, awsKeys, sessions, cookies, refresh, userStore)
	if err != nil {
		return err
	}

	// Workforce federation.
	fedClient, err := federation.NewHTTPClient(cfg.FederationRoots)
	if err != nil {
		return err
	}
	fed := &federation.Handler{
		Issuer:      cfg.FederationIssuer,
		ClientID:    "tallowbrook-idp",
		RedirectURI: cfg.PublicIssuer + "/federation/callback",
		Client:      fedClient,
		Verifier:    federation.NewVerifier(cfg.FederationIssuer, "tallowbrook-idp", cfg.UpstreamAlgs, fedClient),
		Employees:   accounts,
		Log:         log,
	}

	auditLog, err := audit.Open(cfg.AuditDir, 10000)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	browser := http.NewServeMux()
	provider.BrowserRoutes(browser)
	accounts.Routes(browser)
	fed.Routes(browser)
	browser.HandleFunc("GET /healthz", httpx.Health)
	if len(cfg.AvatarURLKey) == 64 {
		av, err := avatars.New(decodeHex(cfg.AvatarURLKey), "https://static.tallowbrook.example", time.Hour)
		if err != nil {
			return err
		}
		browser.Handle("GET /me/avatar", avatarRedirect(av, cookies, sessions))
	}
	enableExperiments(cfg, browser, log)

	tokenMux := http.NewServeMux()
	provider.TokenRoutes(tokenMux)
	tokenSrv, err := mtls.NewServer(cfg.TokenEndpointAddr, cfg.TLSCertFile, cfg.TLSKeyFile, cfg.IssuingCACert, httpx.Stack(log, tokenMux))
	if err != nil {
		return err
	}

	internal, err := newInternal(cfg, log, awsKeys, userStore, tenantStore, auditLog)
	if err != nil {
		return err
	}

	go watchCT(ctx, log, auditLog)
	go refreshRiskRules(ctx, log)

	errc := make(chan error, 3)
	go func() {
		errc <- httpx.Serve(ctx, httpx.NewServer(cfg.ListenAddr, httpx.Stack(log, httpx.SecurityHeaders(browser))), false, log)
	}()
	go func() { errc <- httpx.Serve(ctx, tokenSrv, true, log) }()
	go func() {
		errc <- httpx.Serve(ctx, httpx.NewServer(cfg.InternalAddr, httpx.Stack(log, internal)), false, log)
	}()
	for i := 0; i < 3; i++ {
		if err := <-errc; err != nil {
			stop()
			return err
		}
	}
	return nil
}

func newProvider(cfg *config.Config, log *slog.Logger, awsKeys *kms.Client, sessions *session.Store, cookies *session.CookieCodec, refresh *session.RefreshStore, userStore *users.Store) (*oidc.Provider, error) {
	clients, err := oidc.LoadClients(cfg.ClientsFile)
	if err != nil {
		return nil, err
	}
	idTokens, err := oidc.NewIssuer(cfg.PublicIssuer, cfg.IDTokenKeyFile, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	logout, err := oidc.NewLogoutNotifier(cfg.PublicIssuer, cfg.LogoutTokenKeyFile, log)
	if err != nil {
		return nil, err
	}
	workforce, err := oidc.NewWorkforceSigner(awsKeys, cfg.WorkforceKeyID, cfg.KMSSigningAlg, "wf-2026")
	if err != nil {
		return nil, err
	}
	keySet, err := oidc.NewKeySetFor(idTokens, logout)
	if err != nil {
		return nil, err
	}
	disco, err := oidc.NewDiscovery(cfg.PublicIssuer, cfg.TokenEndpointURL)
	if err != nil {
		return nil, err
	}
	p := &oidc.Provider{
		Issuer:     cfg.PublicIssuer,
		Clients:    clients,
		Sessions:   sessions,
		Cookies:    cookies,
		Refresh:    refresh,
		Accounts:   userStore,
		IDTokens:   idTokens,
		Workforce:  workforce,
		Logout:     logout,
		Discovery:  disco,
		KeySet:     keySet,
		ClientAuth: mtls.ClientID,
		Log:        log,
	}
	p.Init()
	return p, nil
}

func newInternal(cfg *config.Config, log *slog.Logger, awsKeys *kms.Client, userStore *users.Store, tenantStore *tenants.Store, auditLog *audit.Log) (http.Handler, error) {
	mux := http.NewServeMux()
	issuer, err := devicecerts.NewIssuer(cfg.IssuingCACert, cfg.IssuingCAKey)
	if err != nil {
		return nil, err
	}
	escrow, err := recovery.New(cfg.HelpdeskKeyFile, awsKeys, cfg.RecoveryKeyID, 2)
	if err != nil {
		return nil, err
	}
	h := &internalHandlers{
		log:         log,
		users:       userStore,
		tenants:     tenantStore,
		audit:       auditLog,
		devices:     issuer,
		provisioner: provisioning.New(courierRoster{}, "https://api.tallowbrook.example"),
		escrow:      escrow,
		webhooks:    scim.NewWebhooks(scim.NewTenantKeys(tenantStore)),
		kioskKey:    []byte(cfg.KioskKey),
	}
	if len(cfg.TokenizeSecret) > 0 {
		key, err := keyderiv.Derive([]byte(cfg.TokenizeSecret), nil, "account tokens v1", 32)
		if err != nil {
			return nil, err
		}
		if h.tokens, err = tokenize.NewTokenizer(key); err != nil {
			return nil, err
		}
	}
	h.routes(mux)
	return mux, nil
}

func watchCT(ctx context.Context, log *slog.Logger, auditLog *audit.Log) {
	alerts := make(chan ctwatch.Alert, 16)
	w, err := ctwatch.NewHollowmere([]string{
		"CN=Tallowbrook Issuing CA E2-1,O=Tallowbrook",
		"CN=Tallowbrook Issuing CA R2-1,O=Tallowbrook",
	}, alerts, log)
	if err != nil {
		log.Error("ct watch disabled", "err", err)
		return
	}
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-alerts:
			_ = auditLog.Append(audit.Event{Actor: "ctwatch", Action: "foreign-issuance", Target: fmt.Sprint(a.Names), Detail: map[string]string{"issuer": a.Issuer}})
		case <-tick.C:
			if err := w.Poll(ctx); err != nil {
				log.Warn("ct poll", "err", err)
			}
		}
	}
}

func refreshRiskRules(ctx context.Context, log *slog.Logger) {
	f := &release.Fetcher{BaseURL: "https://releases.tallowbrook.example", Client: &http.Client{Timeout: time.Minute}}
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		bundle, err := f.Latest(ctx)
		if err != nil {
			log.Warn("risk rules not updated", "err", err)
		} else {
			log.Info("risk rules updated", "bytes", len(bundle))
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
