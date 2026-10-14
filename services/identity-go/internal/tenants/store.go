package tenants

import (
	"context"
	"crypto/rand"
	"errors"
	"sort"
	"sync"
	"time"

	"tallowbrook.example/identity/internal/scim"
)

var (
	ErrNotFound = errors.New("tenants: not found")
	ErrTaken    = errors.New("tenants: slug already in use")
)

// Store keeps tenants in memory for local runs and tests.
type Store struct {
	mu     sync.RWMutex
	byID   map[string]*Tenant
	bySlug map[string]string
	keys   map[string][]byte
	now    func() time.Time
}

func NewStore() *Store {
	return &Store{byID: make(map[string]*Tenant), bySlug: make(map[string]string), keys: make(map[string][]byte), now: time.Now}
}

// Create validates and stores t.
func (s *Store) Create(_ context.Context, t *Tenant) error {
	if err := t.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.bySlug[t.Slug]; ok {
		return ErrTaken
	}
	t.ID = "t_" + rand.Text()[:12]
	t.Created = s.now()
	t.MaxUsers, _ = UserLimit(t.Plan)
	cp := *t
	s.byID[t.ID] = &cp
	s.bySlug[t.Slug] = t.ID
	return nil
}

// Get returns the tenant with id.
func (s *Store) Get(_ context.Context, id string) (Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byID[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	return *t, nil
}

// BySlug returns the tenant with slug.
func (s *Store) BySlug(ctx context.Context, slug string) (Tenant, error) {
	s.mu.RLock()
	id, ok := s.bySlug[slug]
	s.mu.RUnlock()
	if !ok {
		return Tenant{}, ErrNotFound
	}
	return s.Get(ctx, id)
}

// List returns every tenant, by name.
func (s *Store) List(_ context.Context) []Tenant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0, len(s.byID))
	for _, t := range s.byID {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Suspend blocks sign-in for every user of a tenant.
func (s *Store) Suspend(_ context.Context, id string, suspended bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	t.Suspended = suspended
	return nil
}

// LoadKey implements scim.KeyStorage.
func (s *Store) LoadKey(_ context.Context, tenantID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[tenantID]
	if !ok {
		return nil, scim.ErrNoKey
	}
	return k, nil
}

// SaveKey implements scim.KeyStorage.
func (s *Store) SaveKey(_ context.Context, tenantID string, der []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[tenantID]; !ok {
		return ErrNotFound
	}
	s.keys[tenantID] = append([]byte(nil), der...)
	return nil
}
