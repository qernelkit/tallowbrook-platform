// Package scim sends SCIM provisioning callbacks to tenants. Each tenant gets
// its own signing key; the public half is shown in the tenant console so the
// tenant can check our callbacks.
package scim

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
)

// KeyStorage persists tenant keys (the tenants table in production).
type KeyStorage interface {
	LoadKey(ctx context.Context, tenantID string) ([]byte, error)
	SaveKey(ctx context.Context, tenantID string, pkcs8 []byte) error
}

// ErrNoKey is returned by KeyStorage.LoadKey for tenants without a key.
var ErrNoKey = errors.New("scim: tenant has no key")

// TenantKeys hands out each tenant's webhook key, creating it on first use.
type TenantKeys struct {
	store KeyStorage
	mu    sync.Mutex
	cache map[string]*rsa.PrivateKey
}

func NewTenantKeys(store KeyStorage) *TenantKeys {
	return &TenantKeys{store: store, cache: make(map[string]*rsa.PrivateKey)}
}

// Get returns the tenant's key.
func (t *TenantKeys) Get(ctx context.Context, tenantID string) (*rsa.PrivateKey, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if k, ok := t.cache[tenantID]; ok {
		return k, nil
	}
	raw, err := t.store.LoadKey(ctx, tenantID)
	switch {
	case err == nil:
		k, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("scim: tenant %s: stored key: %w", tenantID, err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("scim: tenant %s: stored key has the wrong type", tenantID)
		}
		t.cache[tenantID] = rk
		return rk, nil
	case errors.Is(err, ErrNoKey):
		return t.create(ctx, tenantID)
	default:
		return nil, err
	}
}

func (t *TenantKeys) create(ctx context.Context, tenantID string) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := t.store.SaveKey(ctx, tenantID, der); err != nil {
		return nil, err
	}
	t.cache[tenantID] = key
	return key, nil
}

// PublicPEM returns the public half for the tenant console.
func (t *TenantKeys) PublicPEM(ctx context.Context, tenantID string) ([]byte, error) {
	k, err := t.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
