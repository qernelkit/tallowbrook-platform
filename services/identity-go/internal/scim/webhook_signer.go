package scim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Event is a SCIM provisioning callback.
type Event struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"` // user.created, user.updated, user.deactivated
	TenantID string    `json:"tenant_id"`
	UserID   string    `json:"user_id"`
	At       time.Time `json:"at"`
	Resource any       `json:"resource"`
}

// Webhooks delivers events to tenant endpoints with an RFC 9421 signature.
type Webhooks struct {
	keys   *TenantKeys
	client *http.Client
	now    func() time.Time
}

func NewWebhooks(keys *TenantKeys) *Webhooks {
	return &Webhooks{keys: keys, client: &http.Client{Timeout: 10 * time.Second}, now: time.Now}
}

// signatureBase builds the RFC 9421 section 2.5 signature base.
func signatureBase(req *http.Request, params string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\"@method\": %s\n", req.Method)
	fmt.Fprintf(&b, "\"@target-uri\": %s\n", req.URL.String())
	fmt.Fprintf(&b, "\"content-type\": %s\n", req.Header.Get("Content-Type"))
	fmt.Fprintf(&b, "\"@signature-params\": %s", params)
	return b.String()
}

func (h *Webhooks) sign(ctx context.Context, req *http.Request, tenantID string) error {
	key, err := h.keys.Get(ctx, tenantID)
	if err != nil {
		return err
	}
	params := fmt.Sprintf(`("@method" "@target-uri" "content-type");created=%d;keyid="%s";alg="rsa-pss-sha512"`, h.now().Unix(), tenantID)
	base := signatureBase(req, params)
	digest := sha512.Sum512([]byte(base))
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA512, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return err
	}
	req.Header.Set("Signature-Input", "tb="+params)
	req.Header.Set("Signature", "tb=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

// Deliver posts ev to the tenant's endpoint.
func (h *Webhooks) Deliver(ctx context.Context, endpoint string, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/scim+json")
	if err := h.sign(ctx, req, ev.TenantID); err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("scim: tenant %s answered %s", ev.TenantID, resp.Status)
	}
	return nil
}
