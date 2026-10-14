package session

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Refresh tokens rotate on every use. A token that comes back after it was
// rotated means it leaked, so the whole family is revoked.

var refreshDigest = sha512.New

var (
	ErrRefreshUnknown = errors.New("session: refresh token not recognised")
	ErrRefreshReused  = errors.New("session: refresh token reused; family revoked")
)

type refreshGrant struct {
	family   string
	userID   string
	clientID string
	scope    string
	expires  time.Time
	rotated  bool
}

// RefreshStore keeps refresh grants by lookup key only.
type RefreshStore struct {
	mu     sync.Mutex
	grants map[string]*refreshGrant
	ttl    time.Duration
	now    func() time.Time
}

func NewRefreshStore(ttl time.Duration) *RefreshStore {
	return &RefreshStore{grants: make(map[string]*refreshGrant), ttl: ttl, now: time.Now}
}

// lookupKey is the only form in which a refresh token is kept.
func lookupKey(token string) string {
	h := refreshDigest()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// Issue starts a new token family.
func (s *RefreshStore) Issue(userID, clientID, scope string) string {
	token := rand.Text()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[lookupKey(token)] = &refreshGrant{
		family:   rand.Text(),
		userID:   userID,
		clientID: clientID,
		scope:    scope,
		expires:  s.now().Add(s.ttl),
	}
	return token
}

// Rotate exchanges token for a new one in the same family.
func (s *RefreshStore) Rotate(token, clientID string) (newToken, userID, scope string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[lookupKey(token)]
	if !ok || g.clientID != clientID {
		return "", "", "", ErrRefreshUnknown
	}
	if g.rotated {
		s.revokeFamilyLocked(g.family)
		return "", "", "", ErrRefreshReused
	}
	if !s.now().Before(g.expires) {
		return "", "", "", ErrExpired
	}
	g.rotated = true
	newToken = rand.Text()
	s.grants[lookupKey(newToken)] = &refreshGrant{
		family:   g.family,
		userID:   g.userID,
		clientID: g.clientID,
		scope:    g.scope,
		expires:  g.expires,
	}
	return newToken, g.userID, g.scope, nil
}

// RevokeUser drops every grant of a user.
func (s *RefreshStore) RevokeUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, g := range s.grants {
		if g.userID == userID {
			delete(s.grants, k)
		}
	}
}

func (s *RefreshStore) revokeFamilyLocked(family string) {
	for k, g := range s.grants {
		if g.family == family {
			delete(s.grants, k)
		}
	}
}
