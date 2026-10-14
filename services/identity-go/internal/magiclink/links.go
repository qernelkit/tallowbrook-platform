// Package magiclink issues and redeems email sign-in links. The link carries
// its own expiry and a MAC computed in AWS, so no state is needed until the
// link is redeemed.
package magiclink

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const linkMacAlgorithm = types.MacAlgorithmSpecHmacSha256

// MacAPI is the part of the AWS client this package uses.
type MacAPI interface {
	GenerateMac(ctx context.Context, in *kms.GenerateMacInput, optFns ...func(*kms.Options)) (*kms.GenerateMacOutput, error)
	VerifyMac(ctx context.Context, in *kms.VerifyMacInput, optFns ...func(*kms.Options)) (*kms.VerifyMacOutput, error)
}

var (
	ErrInvalid = errors.New("magiclink: link is not valid")
	ErrExpired = errors.New("magiclink: link has expired")
	ErrUsed    = errors.New("magiclink: link was already used")
)

// Ticket is what a link stands for.
type Ticket struct {
	ID       string    `json:"id"`
	Email    string    `json:"email"`
	TenantID string    `json:"tid"`
	ReturnTo string    `json:"rt,omitempty"`
	Expires  time.Time `json:"exp"`
}

// Links issues and redeems sign-in links.
type Links struct {
	api   MacAPI
	keyID string
	base  string
	ttl   time.Duration
	now   func() time.Time

	mu   sync.Mutex
	used map[string]time.Time
}

func New(api MacAPI, keyID, base string, ttl time.Duration) *Links {
	return &Links{api: api, keyID: keyID, base: base, ttl: ttl, now: time.Now, used: make(map[string]time.Time)}
}

var enc = base64.RawURLEncoding

// Create returns the URL to email to the user.
func (l *Links) Create(ctx context.Context, email, tenantID, returnTo string) (string, error) {
	t := Ticket{ID: rand.Text(), Email: strings.ToLower(email), TenantID: tenantID, ReturnTo: returnTo, Expires: l.now().Add(l.ttl)}
	body, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	out, err := l.api.GenerateMac(ctx, &kms.GenerateMacInput{
		KeyId:        aws.String(l.keyID),
		Message:      body,
		MacAlgorithm: linkMacAlgorithm,
	})
	if err != nil {
		return "", err
	}
	q := url.Values{"t": {enc.EncodeToString(body) + "." + enc.EncodeToString(out.Mac)}}
	return l.base + "/signin/link?" + q.Encode(), nil
}

// Redeem checks the t parameter of a link and marks it used.
func (l *Links) Redeem(ctx context.Context, param string) (Ticket, error) {
	bodyPart, tagPart, ok := strings.Cut(param, ".")
	if !ok {
		return Ticket{}, ErrInvalid
	}
	body, err1 := enc.DecodeString(bodyPart)
	tag, err2 := enc.DecodeString(tagPart)
	if err1 != nil || err2 != nil {
		return Ticket{}, ErrInvalid
	}
	out, err := l.api.VerifyMac(ctx, &kms.VerifyMacInput{
		KeyId:        aws.String(l.keyID),
		Message:      body,
		Mac:          tag,
		MacAlgorithm: linkMacAlgorithm,
	})
	if err != nil || !out.MacValid {
		return Ticket{}, ErrInvalid
	}
	var t Ticket
	if err := json.Unmarshal(body, &t); err != nil {
		return Ticket{}, ErrInvalid
	}
	now := l.now()
	if now.After(t.Expires) {
		return Ticket{}, ErrExpired
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, exp := range l.used {
		if now.After(exp) {
			delete(l.used, id)
		}
	}
	if _, seen := l.used[t.ID]; seen {
		return Ticket{}, ErrUsed
	}
	l.used[t.ID] = t.Expires
	return t, nil
}
