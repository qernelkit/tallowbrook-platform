package users

import (
	"context"
	"crypto/rand"
	"errors"
	"sort"
	"sync"
	"time"

	"tallowbrook.example/identity/internal/oidc"
	"tallowbrook.example/identity/internal/webauthn"
)

var (
	ErrNotFound  = errors.New("users: not found")
	ErrDuplicate = errors.New("users: email already registered in this tenant")
)

// Store keeps accounts in memory. Production runs the same interface on the
// accounts database; this implementation backs local runs and tests.
type Store struct {
	mu      sync.RWMutex
	byID    map[string]*User
	byEmail map[string]string // tenant/email -> id
	now     func() time.Time
}

func NewStore() *Store {
	return &Store{byID: make(map[string]*User), byEmail: make(map[string]string), now: time.Now}
}

func emailKey(tenantID, email string) string { return tenantID + "/" + email }

// Create adds u and assigns its ID.
func (s *Store) Create(_ context.Context, u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := emailKey(u.TenantID, u.Email)
	if _, ok := s.byEmail[k]; ok {
		return ErrDuplicate
	}
	u.ID = "u_" + rand.Text()[:16]
	u.Created = s.now()
	u.Updated = u.Created
	cp := *u
	s.byID[u.ID] = &cp
	s.byEmail[k] = u.ID
	return nil
}

// Get returns a copy of the user with id.
func (s *Store) Get(_ context.Context, id string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return *u, nil
}

// ByEmail finds a user in a tenant.
func (s *Store) ByEmail(_ context.Context, tenantID, email string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byEmail[emailKey(tenantID, email)]
	if !ok {
		return User{}, ErrNotFound
	}
	return *s.byID[id], nil
}

// Update applies fn to the stored user.
func (s *Store) Update(_ context.Context, id string, fn func(*User) error) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return User{}, ErrNotFound
	}
	cp := *u
	if err := fn(&cp); err != nil {
		return User{}, err
	}
	cp.Updated = s.now()
	if cp.Email != u.Email {
		delete(s.byEmail, emailKey(u.TenantID, u.Email))
		s.byEmail[emailKey(cp.TenantID, cp.Email)] = cp.ID
	}
	s.byID[id] = &cp
	return cp, nil
}

// ByCredential finds the user owning a passkey credential ID.
func (s *Store) ByCredential(_ context.Context, credID string) (User, webauthn.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.byID {
		for _, c := range u.Passkeys {
			if c.ID == credID {
				return *u, c, nil
			}
		}
	}
	return User{}, webauthn.Credential{}, ErrNotFound
}

// ListTenant returns a page of a tenant's users, ordered by email.
func (s *Store) ListTenant(_ context.Context, tenantID string, offset, limit int) []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []User
	for _, u := range s.byID {
		if u.TenantID == tenantID {
			out = append(out, *u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	if offset >= len(out) {
		return nil
	}
	end := min(offset+limit, len(out))
	return out[offset:end]
}

// Account implements oidc.Accounts.
func (s *Store) Account(ctx context.Context, id string) (oidc.Account, error) {
	u, err := s.Get(ctx, id)
	if err != nil {
		return oidc.Account{}, err
	}
	if u.Status == StatusDisabled {
		return oidc.Account{}, ErrNotFound
	}
	return oidc.Account{ID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.Name, TenantID: u.TenantID}, nil
}
