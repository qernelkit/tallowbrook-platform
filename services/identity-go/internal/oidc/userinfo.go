package oidc

import (
	"net/http"
	"slices"
	"strings"
)

type userinfoResponse struct {
	Subject       string `json:"sub"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	TenantID      string `json:"tid,omitempty"`
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	t, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || t == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tallowbrook"`)
		http.Error(w, "missing access token", http.StatusUnauthorized)
		return
	}
	g, ok := p.access.lookup(t, p.now())
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	acct, err := p.Accounts.Account(r.Context(), g.userID)
	if err != nil {
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}
	resp := userinfoResponse{Subject: acct.ID, TenantID: acct.TenantID}
	if slices.Contains(g.scope, "profile") {
		resp.Name = acct.Name
	}
	if slices.Contains(g.scope, "email") {
		resp.Email = acct.Email
		resp.EmailVerified = acct.EmailVerified
	}
	writeJSON(w, resp)
}
