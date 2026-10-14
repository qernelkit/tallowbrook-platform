// Package config reads the identity service settings from the environment.
//
// Every binary in this module calls Load once at start-up. Defaults match the
// production layout on the identity hosts, so a local run only needs the
// secrets that have no default.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the settings shared by the identity binaries.
type Config struct {
	ListenAddr   string
	InternalAddr string
	PublicIssuer string
	AWSRegion    string
	LogLevel     string

	// Customer realm token keys (PEM files on the host).
	IDTokenKeyFile     string
	LogoutTokenKeyFile string

	// Workforce realm: ID tokens are signed inside AWS.
	WorkforceKeyID string
	KMSSigningAlg  string

	SessionKeyARN  string
	SessionTTL     time.Duration
	SessionShards  int
	CookieSecret   string
	RefreshTTL     time.Duration
	MagicLinkKeyID string
	MagicLinkTTL   time.Duration
	RecoveryKeyID  string
	AvatarURLKey   string

	// RFC 8705 token endpoint.
	TokenEndpointAddr string
	TLSCertFile       string
	TLSKeyFile        string
	IssuingCACert     string
	IssuingCAKey      string

	// Upstream workforce IdP.
	FederationIssuer string
	FederationRoots  string
	UpstreamAlgs     []string

	// SSH certificate authority.
	SSHUserCAKey        string
	SSHUserCAPub        string
	SSHUserCAPassphrase string
	EnrollAddr          string
	EnrollHostKey       string
	KRLPushKey          string
	KRLPushCert         string
	BastionKnownHosts   string
	Bastions            []string
	UserCertTTL         time.Duration

	// Recording bridge for support calls.
	BridgeHost string
	BridgeAddr string

	ClientsFile         string
	TokenEndpointURL    string
	KioskKey            string
	AnonLoginKey        string
	HelpdeskKeyFile     string
	AuditRecipientsFile string
	AuditDir            string
	CourierKeysDir      string
	RelayAddr           string
	RelaySecret         string
	TokenizeSecret      string

	Experiments []string
}

// Load reads the environment. It fails only on values that cannot be parsed.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:   getenv("IDP_LISTEN_ADDR", ":8080"),
		InternalAddr: getenv("IDP_INTERNAL_ADDR", "10.40.0.10:9090"),
		PublicIssuer: getenv("IDP_ISSUER", "https://id.tallowbrook.example"),
		AWSRegion:    getenv("AWS_REGION", "eu-west-1"),
		LogLevel:     getenv("IDP_LOG_LEVEL", "info"),

		IDTokenKeyFile:     getenv("IDP_ID_TOKEN_KEY", "/etc/tallowbrook/pki/keys/token-signing-es256.pem"),
		LogoutTokenKeyFile: getenv("IDP_LOGOUT_TOKEN_KEY", "/etc/tallowbrook/pki/keys/token-signing-ed25519.pem"),

		WorkforceKeyID: getenv("IDP_WORKFORCE_KEY", "alias/identity-workforce-tokens"),
		KMSSigningAlg:  getenv("IDP_KMS_SIGNING_ALG", "ECDSA_SHA_384"),

		SessionKeyARN:  getenv("IDP_SESSION_KEY", "alias/identity-sessions"),
		CookieSecret:   os.Getenv("IDP_COOKIE_SECRET"),
		MagicLinkKeyID: getenv("IDP_MAGIC_LINK_KEY", "alias/identity-magic-links"),
		RecoveryKeyID:  getenv("IDP_RECOVERY_KEY", "alias/identity-recovery"),
		AvatarURLKey:   os.Getenv("IDP_AVATAR_URL_KEY"),

		TokenEndpointAddr: getenv("IDP_TOKEN_ENDPOINT_ADDR", ":8443"),
		TLSCertFile:       getenv("IDP_TLS_CERT", "/etc/tallowbrook/pki/services/api.crt"),
		TLSKeyFile:        getenv("IDP_TLS_KEY", "/etc/tallowbrook/pki/services/api.key"),
		IssuingCACert:     getenv("IDP_ISSUING_CA_CERT", "/etc/tallowbrook/pki/ca/issuing-ec.crt"),
		IssuingCAKey:      getenv("IDP_ISSUING_CA_KEY", "/etc/tallowbrook/pki/ca/issuing-ec.key"),

		FederationIssuer: getenv("IDP_FEDERATION_ISSUER", "https://login.corp.tallowbrook.example"),
		FederationRoots:  getenv("IDP_FEDERATION_ROOTS", "/etc/tallowbrook/pki/ca/root-ec-2024.crt"),
		UpstreamAlgs:     splitList(getenv("IDP_UPSTREAM_ALGS", "RS256,ES256")),

		SSHUserCAKey:        getenv("SSHCA_USER_CA_KEY", "/etc/tallowbrook/pki/ssh/user_ca"),
		SSHUserCAPub:        getenv("SSHCA_USER_CA_PUB", "/etc/tallowbrook/pki/ssh/user_ca.pub"),
		SSHUserCAPassphrase: os.Getenv("SSHCA_USER_CA_PASSPHRASE"),
		EnrollAddr:          getenv("SSHCA_ENROLL_ADDR", ":2222"),
		EnrollHostKey:       getenv("SSHCA_ENROLL_HOST_KEY", "/var/lib/identity/enroll/host_key"),
		KRLPushKey:          getenv("SSHCA_KRL_PUSH_KEY", "/etc/tallowbrook/pki/ssh/deploy_ed25519"),
		KRLPushCert:         getenv("SSHCA_KRL_PUSH_CERT", "/etc/tallowbrook/pki/ssh/deploy_ed25519-cert.pub"),
		BastionKnownHosts:   getenv("SSHCA_KNOWN_HOSTS", "/etc/tallowbrook/pki/ssh/known_hosts"),
		Bastions:            splitList(getenv("SSHCA_BASTIONS", "bastion-a.tallowbrook.example:22,bastion-b.tallowbrook.example:22")),

		BridgeHost: getenv("SIGNAL_BRIDGE_HOST", "bridge.signal.tallowbrook.example"),
		BridgeAddr: getenv("SIGNAL_BRIDGE_ADDR", ":5004"),

		ClientsFile:         getenv("IDP_CLIENTS_FILE", "/etc/tallowbrook/identity/clients.json"),
		TokenEndpointURL:    getenv("IDP_TOKEN_URL", "https://token.id.tallowbrook.example"),
		KioskKey:            os.Getenv("IDP_KIOSK_KEY"),
		AnonLoginKey:        getenv("IDP_ANON_LOGIN_KEY", "/var/lib/identity/anon-login/issuer.pem"),
		HelpdeskKeyFile:     getenv("IDP_HELPDESK_KEY", "/etc/tallowbrook/identity/helpdesk-recovery.pem"),
		AuditRecipientsFile: getenv("IDP_AUDIT_RECIPIENTS", "/etc/tallowbrook/identity/audit-recipients.asc"),
		AuditDir:            getenv("IDP_AUDIT_DIR", "/var/lib/identity/audit"),
		CourierKeysDir:      getenv("IDP_COURIER_KEYS", "/var/lib/identity/courier-keys"),
		RelayAddr:           getenv("IDP_RELAY_ADDR", "relay.depot.tallowbrook.example:587"),
		RelaySecret:         os.Getenv("IDP_RELAY_SECRET"),
		TokenizeSecret:      os.Getenv("IDP_TOKENIZE_SECRET"),

		Experiments: splitList(os.Getenv("IDP_EXPERIMENTS")),
	}

	var err error
	if c.SessionTTL, err = durationEnv("IDP_SESSION_TTL", 12*time.Hour); err != nil {
		return nil, err
	}
	if c.RefreshTTL, err = durationEnv("IDP_REFRESH_TTL", 30*24*time.Hour); err != nil {
		return nil, err
	}
	if c.MagicLinkTTL, err = durationEnv("IDP_MAGIC_LINK_TTL", 15*time.Minute); err != nil {
		return nil, err
	}
	if c.UserCertTTL, err = durationEnv("SSHCA_USER_CERT_TTL", 8*time.Hour); err != nil {
		return nil, err
	}
	if c.SessionShards, err = intEnv("IDP_SESSION_SHARDS", 16); err != nil {
		return nil, err
	}
	return c, nil
}

// Enabled reports whether the named experiment flag is switched on.
func (c *Config) Enabled(name string) bool {
	for _, e := range c.Experiments {
		if e == name {
			return true
		}
	}
	return false
}

func getenv(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

func durationEnv(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("config: %s must be positive", name)
	}
	return d, nil
}

func intEnv(name string, def int) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("config: %s must be a positive integer", name)
	}
	return n, nil
}

// splitList turns "a, b,,c" into [a b c].
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
