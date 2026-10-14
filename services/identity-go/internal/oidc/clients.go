package oidc

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sync"

	"github.com/go-jose/go-jose/v4"

	"tallowbrook.example/identity/internal/session"
)

// Client is a registered relying party.
type Client struct {
	ID                   string        `json:"client_id"`
	Name                 string        `json:"client_name"`
	TenantID             string        `json:"tenant_id"`
	Realm                session.Realm `json:"realm"`
	RedirectURIs         []string      `json:"redirect_uris"`
	Public               bool          `json:"public"`
	Scopes               []string      `json:"scopes"`
	BackchannelLogoutURI string        `json:"backchannel_logout_uri,omitempty"`
}

// AllowsRedirect reports whether uri is registered for the client, compared
// exactly as RFC 9700 asks.
func (c *Client) AllowsRedirect(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

// AllowsScope reports whether every requested scope is registered.
func (c *Client) AllowsScope(scopes []string) bool {
	for _, s := range scopes {
		if !slices.Contains(c.Scopes, s) {
			return false
		}
	}
	return true
}

// clientEncryption is set for relying parties that receive their ID tokens
// encrypted to a key they registered with us.
type clientEncryption struct {
	KeyAlg     jose.KeyAlgorithm
	ContentEnc jose.ContentEncryption
	KeyFile    string
}

var encryptedClients = map[string]clientEncryption{
	"harborline-portal": {
		KeyAlg:     jose.RSA_OAEP_256,
		ContentEnc: jose.A256GCM,
		KeyFile:    "/etc/tallowbrook/identity/rp/harborline-portal.pub.pem",
	},
}

// ClientRegistry holds the registered relying parties.
type ClientRegistry struct {
	mu      sync.RWMutex
	clients map[string]*Client
}

// LoadClients reads the registration file written by the tenant console.
func LoadClients(path string) (*ClientRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []*Client
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("oidc: %s: %w", path, err)
	}
	reg := &ClientRegistry{clients: make(map[string]*Client, len(list))}
	for _, c := range list {
		if err := c.validate(); err != nil {
			return nil, err
		}
		reg.clients[c.ID] = c
	}
	return reg, nil
}

// NewClientRegistry builds a registry from clients already in memory.
func NewClientRegistry(clients ...*Client) *ClientRegistry {
	reg := &ClientRegistry{clients: make(map[string]*Client, len(clients))}
	for _, c := range clients {
		reg.clients[c.ID] = c
	}
	return reg
}

// Get returns the client with the given ID.
func (r *ClientRegistry) Get(id string) (*Client, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[id]
	return c, ok
}

// WithLogout returns the clients that registered a back-channel logout URI.
func (r *ClientRegistry) WithLogout(ids []string) []*Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Client
	for _, id := range ids {
		if c, ok := r.clients[id]; ok && c.BackchannelLogoutURI != "" {
			out = append(out, c)
		}
	}
	return out
}

func (c *Client) validate() error {
	if c.ID == "" || len(c.RedirectURIs) == 0 {
		return fmt.Errorf("oidc: client %q: id and redirect_uris are required", c.ID)
	}
	for _, raw := range c.RedirectURIs {
		u, err := url.Parse(raw)
		if err != nil || u.Fragment != "" {
			return fmt.Errorf("oidc: client %q: bad redirect URI %q", c.ID, raw)
		}
		if u.Scheme != "https" && !(c.Public && u.Hostname() == "127.0.0.1") {
			return fmt.Errorf("oidc: client %q: redirect URI must be https: %q", c.ID, raw)
		}
	}
	switch c.Realm {
	case session.RealmCustomer, session.RealmWorkforce:
	default:
		return fmt.Errorf("oidc: client %q: unknown realm %q", c.ID, c.Realm)
	}
	return nil
}
