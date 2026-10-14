package oidc

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"tallowbrook.example/identity/internal/session"
)

var supportedScopes = []string{"openid", "profile", "email", "offline_access"}

// authRequest is a parsed authorization request.
type authRequest struct {
	client      *Client
	redirectURI string
	state       string
	nonce       string
	scope       []string
	challenge   string
	method      string
	prompt      string
}

type authError struct {
	code        string
	description string
}

func (e *authError) Error() string { return e.code + ": " + e.description }

func parseAuthRequest(q url.Values, clients *ClientRegistry) (*authRequest, *authError, bool) {
	c, ok := clients.Get(q.Get("client_id"))
	if !ok {
		return nil, &authError{"invalid_request", "unknown client_id"}, false
	}
	redirect := q.Get("redirect_uri")
	if !c.AllowsRedirect(redirect) {
		// Never redirect to an unregistered URI; show the error instead.
		return nil, &authError{"invalid_request", "redirect_uri is not registered"}, false
	}
	req := &authRequest{
		client:      c,
		redirectURI: redirect,
		state:       q.Get("state"),
		nonce:       q.Get("nonce"),
		scope:       strings.Fields(q.Get("scope")),
		challenge:   q.Get("code_challenge"),
		method:      q.Get("code_challenge_method"),
		prompt:      q.Get("prompt"),
	}
	if q.Get("response_type") != "code" {
		return req, &authError{"unsupported_response_type", "only the code flow is supported"}, true
	}
	if !slices.Contains(req.scope, supportedScopes[0]) {
		return req, &authError{"invalid_scope", "the openid scope is required"}, true
	}
	if !c.AllowsScope(req.scope) {
		return req, &authError{"invalid_scope", "scope not allowed for this client"}, true
	}
	if req.challenge == "" {
		return req, &authError{"invalid_request", "code_challenge is required"}, true
	}
	if err := checkChallengeMethod(req.method); err != nil {
		return req, &authError{"invalid_request", err.Error()}, true
	}
	if len(req.state) > 512 || len(req.nonce) > 512 {
		return req, &authError{"invalid_request", "state or nonce too long"}, true
	}
	return req, nil, true
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	req, aerr, canRedirect := parseAuthRequest(r.URL.Query(), p.Clients)
	if aerr != nil {
		if !canRedirect {
			http.Error(w, aerr.Error(), http.StatusBadRequest)
			return
		}
		p.redirectError(w, r, req, aerr)
		return
	}
	sess, ok := p.currentSession(r, req.client.Realm)
	if !ok || req.prompt == "login" {
		if req.prompt == "none" {
			p.redirectError(w, r, req, &authError{"login_required", "no active session"})
			return
		}
		back := url.Values{"return_to": {r.URL.RequestURI()}, "realm": {string(req.client.Realm)}}
		http.Redirect(w, r, p.signInAt+"?"+back.Encode(), http.StatusFound)
		return
	}
	code := p.codes.issue(&authCode{
		clientID:    req.client.ID,
		redirectURI: req.redirectURI,
		userID:      sess.UserID,
		sessionID:   sess.ID,
		scope:       req.scope,
		nonce:       req.nonce,
		challenge:   req.challenge,
		method:      req.method,
		authTime:    sess.IssuedAt,
		methods:     sess.AuthMethods,
		expires:     p.now().Add(codeLifetime),
	})
	v := url.Values{"code": {code}, "iss": {p.Issuer}}
	if req.state != "" {
		v.Set("state", req.state)
	}
	http.Redirect(w, r, appendQuery(req.redirectURI, v), http.StatusFound)
}

func (p *Provider) currentSession(r *http.Request, realm session.Realm) (session.Session, bool) {
	sid, cookieRealm, err := p.Cookies.Read(r, p.now())
	if err != nil || cookieRealm != realm {
		return session.Session{}, false
	}
	sess, err := p.Sessions.Get(r.Context(), sid)
	if err != nil {
		return session.Session{}, false
	}
	if p.now().Sub(sess.LastSeen) > 30*time.Minute {
		_ = p.Sessions.Touch(r.Context(), sid)
	}
	return sess, true
}

func (p *Provider) redirectError(w http.ResponseWriter, r *http.Request, req *authRequest, e *authError) {
	v := url.Values{"error": {e.code}, "error_description": {e.description}, "iss": {p.Issuer}}
	if req.state != "" {
		v.Set("state", req.state)
	}
	http.Redirect(w, r, appendQuery(req.redirectURI, v), http.StatusFound)
}

func appendQuery(base string, v url.Values) string {
	if strings.Contains(base, "?") {
		return base + "&" + v.Encode()
	}
	return base + "?" + v.Encode()
}
