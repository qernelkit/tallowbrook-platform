package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"tallowbrook.example/identity/internal/session"
)

const (
	accessTokenLifetime = 10 * time.Minute
	idTokenLifetime     = 10 * time.Minute
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type tokenError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func writeTokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(tokenError{Error: code, Description: desc})
}

// authenticateClient identifies the caller: confidential clients by their
// certificate, public clients by client_id alone (PKCE protects the code).
func (p *Provider) authenticateClient(r *http.Request) (*Client, error) {
	if id, ok := p.ClientAuth(r); ok {
		c, found := p.Clients.Get(id)
		if !found || c.Public {
			return nil, errors.New("client certificate does not match a confidential client")
		}
		return c, nil
	}
	c, found := p.Clients.Get(r.PostForm.Get("client_id"))
	if !found || !c.Public {
		return nil, errors.New("client authentication required")
	}
	return c, nil
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	client, err := p.authenticateClient(r)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.exchangeCode(w, r, client)
	case "refresh_token":
		p.exchangeRefresh(w, r, client)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (p *Provider) exchangeCode(w http.ResponseWriter, r *http.Request, client *Client) {
	code, ok := p.codes.redeem(r.PostForm.Get("code"), p.now())
	if !ok || code.clientID != client.ID || code.redirectURI != r.PostForm.Get("redirect_uri") {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "code is invalid or expired")
		return
	}
	if err := verifyPKCE(code.method, code.challenge, r.PostForm.Get("code_verifier")); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	acct, err := p.Accounts.Account(r.Context(), code.userID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "account no longer exists")
		return
	}
	idToken, err := p.idTokenFor(r, client, acct, code)
	if err != nil {
		p.Log.Error("id token", "client", client.ID, "err", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	resp := tokenResponse{
		AccessToken: p.access.issue(accessGrant{userID: acct.ID, clientID: client.ID, scope: code.scope, expires: p.now().Add(accessTokenLifetime)}),
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTokenLifetime.Seconds()),
		IDToken:     idToken,
		Scope:       strings.Join(code.scope, " "),
	}
	if slices.Contains(code.scope, "offline_access") {
		resp.RefreshToken = p.Refresh.Issue(acct.ID, client.ID, resp.Scope)
	}
	writeJSON(w, resp)
}

func (p *Provider) idTokenFor(r *http.Request, client *Client, acct Account, code *authCode) (string, error) {
	req := TokenRequest{
		Subject:   acct.ID,
		ClientID:  client.ID,
		Nonce:     code.nonce,
		SessionID: code.sessionID,
		AuthTime:  code.authTime,
		Methods:   code.methods,
		Email:     acct.Email,
		Verified:  acct.EmailVerified,
		TenantID:  acct.TenantID,
	}
	var signed string
	var err error
	if client.Realm == session.RealmWorkforce {
		c := p.IDTokens.claims(req)
		signed, err = p.Workforce.Sign(r.Context(), map[string]any{
			"iss": c.Issuer, "sub": c.Subject, "aud": client.ID,
			"iat": c.IssuedAt.Unix(), "exp": c.ExpiresAt.Unix(),
			"auth_time": c.AuthTime, "amr": c.AMR, "sid": c.SID, "email": c.Email,
		})
	} else {
		signed, err = p.IDTokens.IDToken(req)
	}
	if err != nil {
		return "", err
	}
	return p.wrapper.wrap(client.ID, signed)
}

func (p *Provider) exchangeRefresh(w http.ResponseWriter, r *http.Request, client *Client) {
	next, userID, scope, err := p.Refresh.Rotate(r.PostForm.Get("refresh_token"), client.ID)
	if err != nil {
		if errors.Is(err, session.ErrRefreshReused) {
			p.Log.Warn("refresh token reuse", "client", client.ID)
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
		return
	}
	writeJSON(w, tokenResponse{
		AccessToken:  p.access.issue(accessGrant{userID: userID, clientID: client.ID, scope: strings.Fields(scope), expires: p.now().Add(accessTokenLifetime)}),
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTokenLifetime.Seconds()),
		RefreshToken: next,
		Scope:        scope,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
