package oidc

import (
	"crypto/rand"
	"sync"
	"time"
)

const codeLifetime = 60 * time.Second

// authCode is an issued authorization code and what it stands for.
type authCode struct {
	clientID    string
	redirectURI string
	userID      string
	sessionID   string
	scope       []string
	nonce       string
	challenge   string
	method      string
	authTime    time.Time
	methods     []string
	expires     time.Time
}

type codeStore struct {
	mu    sync.Mutex
	codes map[string]*authCode
	// clients that received a code per session, for back-channel logout
	bySession map[string]map[string]bool
}

func newCodeStore() *codeStore {
	return &codeStore{codes: make(map[string]*authCode), bySession: make(map[string]map[string]bool)}
}

func (s *codeStore) issue(c *authCode) string {
	code := rand.Text()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = c
	if s.bySession[c.sessionID] == nil {
		s.bySession[c.sessionID] = make(map[string]bool)
	}
	s.bySession[c.sessionID][c.clientID] = true
	return code
}

// redeem returns the code and deletes it; codes are single use.
func (s *codeStore) redeem(code string, now time.Time) (*authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	delete(s.codes, code)
	if !ok || now.After(c.expires) {
		return nil, false
	}
	return c, true
}

func (s *codeStore) clientsFor(sessionID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.bySession[sessionID]))
	for id := range s.bySession[sessionID] {
		out = append(out, id)
	}
	delete(s.bySession, sessionID)
	return out
}

// accessGrant is what an opaque access token stands for.
type accessGrant struct {
	userID   string
	clientID string
	scope    []string
	expires  time.Time
}

type accessStore struct {
	mu     sync.Mutex
	grants map[string]accessGrant
}

func newAccessStore() *accessStore {
	return &accessStore{grants: make(map[string]accessGrant)}
}

func (s *accessStore) issue(g accessGrant) string {
	t := rand.Text()
	s.mu.Lock()
	s.grants[t] = g
	s.mu.Unlock()
	return t
}

func (s *accessStore) lookup(t string, now time.Time) (accessGrant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[t]
	if !ok || now.After(g.expires) {
		delete(s.grants, t)
		return accessGrant{}, false
	}
	return g, true
}
