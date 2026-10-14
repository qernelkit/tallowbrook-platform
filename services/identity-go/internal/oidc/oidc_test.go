package oidc

import (
	"net/url"
	"strings"
	"testing"

	"tallowbrook.example/identity/internal/session"
)

func testClients() *ClientRegistry {
	return NewClientRegistry(
		&Client{
			ID:           "depot-portal",
			Realm:        session.RealmWorkforce,
			RedirectURIs: []string{"https://depot.tallowbrook.example/callback"},
			Scopes:       supportedScopes,
		},
		&Client{
			ID:           "courier-app",
			Realm:        session.RealmCustomer,
			Public:       true,
			RedirectURIs: []string{"http://127.0.0.1:7777/cb"},
			Scopes:       []string{supportedScopes[0], "profile"},
		},
	)
}

func authQuery(over map[string]string) url.Values {
	q := url.Values{
		"client_id":             {"depot-portal"},
		"redirect_uri":          {"https://depot.tallowbrook.example/callback"},
		"response_type":         {"code"},
		"scope":                 {supportedScopes[0] + " profile"},
		"state":                 {"xyz"},
		"code_challenge":        {strings.Repeat("A", 43)},
		"code_challenge_method": {"S256"},
	}
	for k, v := range over {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q
}

func TestParseAuthRequest(t *testing.T) {
	tests := []struct {
		name        string
		over        map[string]string
		wantCode    string
		canRedirect bool
	}{
		{"valid", nil, "", true},
		{"unknown client", map[string]string{"client_id": "nobody"}, "invalid_request", false},
		{"unregistered redirect", map[string]string{"redirect_uri": "https://evil.example/cb"}, "invalid_request", false},
		{"implicit flow", map[string]string{"response_type": "token"}, "unsupported_response_type", true},
		{"missing base scope", map[string]string{"scope": "profile"}, "invalid_scope", true},
		{"scope not allowed", map[string]string{"client_id": "courier-app", "redirect_uri": "http://127.0.0.1:7777/cb", "scope": supportedScopes[0] + " email"}, "invalid_scope", true},
		{"no challenge", map[string]string{"code_challenge": ""}, "invalid_request", true},
		{"plain challenge", map[string]string{"code_challenge_method": "plain"}, "invalid_request", true},
		{"huge state", map[string]string{"state": strings.Repeat("s", 600)}, "invalid_request", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, aerr, canRedirect := parseAuthRequest(authQuery(tt.over), testClients())
			got := ""
			if aerr != nil {
				got = aerr.code
			}
			if got != tt.wantCode {
				t.Errorf("error code = %q, want %q", got, tt.wantCode)
			}
			if canRedirect != tt.canRedirect {
				t.Errorf("canRedirect = %v, want %v", canRedirect, tt.canRedirect)
			}
		})
	}
}

func TestValidVerifier(t *testing.T) {
	tests := []struct {
		v    string
		want bool
	}{
		{strings.Repeat("a", 43), true},
		{strings.Repeat("a", 128), true},
		{strings.Repeat("a", 42), false},
		{strings.Repeat("a", 129), false},
		{strings.Repeat("a", 42) + "~", true},
		{strings.Repeat("a", 42) + "+", false},
		{strings.Repeat("a", 42) + " ", false},
	}
	for _, tt := range tests {
		if got := validVerifier(tt.v); got != tt.want {
			t.Errorf("validVerifier(len %d, last %q) = %v", len(tt.v), tt.v[len(tt.v)-1:], got)
		}
	}
}

func TestAppendQuery(t *testing.T) {
	v := url.Values{"code": {"abc"}, "state": {"x y"}}
	if got := appendQuery("https://rp.example/cb", v); got != "https://rp.example/cb?code=abc&state=x+y" {
		t.Errorf("got %q", got)
	}
	if got := appendQuery("https://rp.example/cb?tenant=7", v); got != "https://rp.example/cb?tenant=7&code=abc&state=x+y" {
		t.Errorf("got %q", got)
	}
}

func TestClientValidate(t *testing.T) {
	tests := []struct {
		name string
		c    Client
		ok   bool
	}{
		{"web client", Client{ID: "a", Realm: session.RealmCustomer, RedirectURIs: []string{"https://a.example/cb"}}, true},
		{"loopback public client", Client{ID: "b", Realm: session.RealmCustomer, Public: true, RedirectURIs: []string{"http://127.0.0.1:9000/cb"}}, true},
		{"loopback confidential client", Client{ID: "c", Realm: session.RealmCustomer, RedirectURIs: []string{"http://127.0.0.1:9000/cb"}}, false},
		{"fragment", Client{ID: "d", Realm: session.RealmCustomer, RedirectURIs: []string{"https://a.example/cb#x"}}, false},
		{"no realm", Client{ID: "e", RedirectURIs: []string{"https://a.example/cb"}}, false},
		{"no redirect", Client{ID: "f", Realm: session.RealmCustomer}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.validate(); (err == nil) != tt.ok {
				t.Errorf("validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestCodeStoreSingleUse(t *testing.T) {
	s := newCodeStore()
	p := &Provider{}
	p.Init()
	code := s.issue(&authCode{clientID: "a", sessionID: "s1", expires: p.now().Add(codeLifetime)})
	if _, ok := s.redeem(code, p.now()); !ok {
		t.Fatal("fresh code refused")
	}
	if _, ok := s.redeem(code, p.now()); ok {
		t.Fatal("code redeemed twice")
	}
	if got := s.clientsFor("s1"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("clientsFor = %v", got)
	}
}
