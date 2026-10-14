package federation

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Employees signs in employees once the upstream IdP has vouched for them.
type Employees interface {
	SignInEmployee(ctx context.Context, w http.ResponseWriter, r *http.Request, c *UpstreamClaims) error
}

// Handler runs the authorization code flow against the corporate IdP.
type Handler struct {
	Issuer      string // upstream issuer URL
	ClientID    string
	RedirectURI string
	Client      *http.Client
	Verifier    *Verifier
	Employees   Employees
	Log         *slog.Logger

	mu      sync.Mutex
	pending map[string]pendingLogin
}

type pendingLogin struct {
	returnTo string
	expires  time.Time
}

// Routes registers the federation endpoints.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /federation/start", h.start)
	mux.HandleFunc("GET /federation/callback", h.callback)
}

func (h *Handler) start(w http.ResponseWriter, r *http.Request) {
	state := rand.Text()
	h.mu.Lock()
	if h.pending == nil {
		h.pending = make(map[string]pendingLogin)
	}
	now := time.Now()
	for k, p := range h.pending {
		if now.After(p.expires) {
			delete(h.pending, k)
		}
	}
	h.pending[state] = pendingLogin{returnTo: r.URL.Query().Get("return_to"), expires: now.Add(10 * time.Minute)}
	h.mu.Unlock()
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {h.ClientID},
		"redirect_uri":  {h.RedirectURI},
		"scope":         {"openid email profile"},
		"state":         {state},
	}
	http.Redirect(w, r, h.Issuer+"/oauth2/authorize?"+q.Encode(), http.StatusFound)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	h.mu.Lock()
	p, ok := h.pending[q.Get("state")]
	delete(h.pending, q.Get("state"))
	h.mu.Unlock()
	if !ok || time.Now().After(p.expires) {
		http.Error(w, "sign-in expired; start again", http.StatusBadRequest)
		return
	}
	if e := q.Get("error"); e != "" {
		h.Log.Info("upstream refused sign-in", "error", e)
		http.Redirect(w, r, "/signin?error=upstream", http.StatusSeeOther)
		return
	}
	raw, err := h.exchange(r.Context(), q.Get("code"))
	if err != nil {
		h.Log.Error("upstream code exchange", "err", err)
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}
	claims, err := h.Verifier.Verify(r.Context(), raw)
	if err != nil {
		h.Log.Warn("upstream token", "err", err)
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
		return
	}
	if err := h.Employees.SignInEmployee(r.Context(), w, r, claims); err != nil {
		h.Log.Error("employee sign-in", "employee", claims.EmployeeID, "err", err)
		http.Error(w, "sign-in failed", http.StatusForbidden)
		return
	}
	dest := p.returnTo
	if !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (h *Handler) exchange(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {h.RedirectURI},
		"client_id":    {h.ClientID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.Issuer+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint answered %s", resp.Status)
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.IDToken, nil
}
