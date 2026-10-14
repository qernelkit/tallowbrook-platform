// Package oidc is the OpenID Connect provider: authorization, token,
// userinfo, discovery and key set endpoints, and back-channel logout.
package oidc

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"tallowbrook.example/identity/internal/session"
)

// Account is what the provider needs to know about a signed-in user.
type Account struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	TenantID      string
}

// Accounts looks up users by ID.
type Accounts interface {
	Account(ctx context.Context, id string) (Account, error)
}

// ClientAuthenticator returns the client ID proven by the transport (the
// client certificate on the token endpoint), if any.
type ClientAuthenticator func(r *http.Request) (string, bool)

// Provider wires the endpoints together.
type Provider struct {
	Issuer     string
	Clients    *ClientRegistry
	Sessions   *session.Store
	Cookies    *session.CookieCodec
	Refresh    *session.RefreshStore
	Accounts   Accounts
	IDTokens   *Issuer
	Workforce  *WorkforceSigner
	Logout     *LogoutNotifier
	Discovery  *Discovery
	KeySet     *KeySet
	ClientAuth ClientAuthenticator
	Log        *slog.Logger

	codes    *codeStore
	access   *accessStore
	wrapper  *tokenWrapper
	signInAt string
	now      func() time.Time
}

// Init prepares the internal stores. Call it once before serving.
func (p *Provider) Init() {
	p.codes = newCodeStore()
	p.access = newAccessStore()
	p.wrapper = newTokenWrapper()
	p.signInAt = "/signin"
	p.now = time.Now
}

// BrowserRoutes registers the endpoints a browser reaches.
func (p *Provider) BrowserRoutes(mux *http.ServeMux) {
	mux.Handle("GET /.well-known/openid-configuration", p.Discovery)
	mux.Handle("GET /jwks.json", p.KeySet)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	mux.HandleFunc("POST /logout", p.endSession)
}

// TokenRoutes registers the token endpoint, which listens on its own port.
func (p *Provider) TokenRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /token", p.token)
}

func (p *Provider) endSession(w http.ResponseWriter, r *http.Request) {
	sid, _, err := p.Cookies.Read(r, p.now())
	p.Cookies.Clear(w)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	sess, err := p.Sessions.Get(r.Context(), sid)
	if err == nil {
		p.Sessions.Delete(sid)
		p.Refresh.RevokeUser(sess.UserID)
		clients := p.Clients.WithLogout(p.codes.clientsFor(sid))
		go p.Logout.Notify(context.WithoutCancel(r.Context()), clients, sess.UserID, sid)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
