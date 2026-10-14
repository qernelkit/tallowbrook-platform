// Package avatars hands out expiring URLs for profile pictures, which are
// served by the static edge without asking the IdP.
package avatars

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/crypto/blake2b"
)

// URLs signs and checks avatar URLs.
type URLs struct {
	key  []byte
	base string
	ttl  time.Duration
	now  func() time.Time
}

// New takes the 32-byte key shared with the edge.
func New(key []byte, base string, ttl time.Duration) (*URLs, error) {
	if len(key) != 32 {
		return nil, errors.New("avatars: key must be 32 bytes")
	}
	return &URLs{key: key, base: base, ttl: ttl, now: time.Now}, nil
}

func (u *URLs) tag(path string, exp int64) ([]byte, error) {
	mac, err := blake2b.New256(u.key)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(mac, "%s\n%d", path, exp)
	return mac.Sum(nil), nil
}

// For returns the URL of userID's avatar at the given pixel size.
func (u *URLs) For(userID string, size int) (string, error) {
	switch size {
	case 32, 64, 128, 256:
	default:
		return "", fmt.Errorf("avatars: unsupported size %d", size)
	}
	path := fmt.Sprintf("/avatars/%s/%d.webp", url.PathEscape(userID), size)
	exp := u.now().Add(u.ttl).Unix()
	t, err := u.tag(path, exp)
	if err != nil {
		return "", err
	}
	q := url.Values{"e": {strconv.FormatInt(exp, 10)}, "s": {hex.EncodeToString(t)}}
	return u.base + path + "?" + q.Encode(), nil
}

// Check is the edge's test, kept here so both sides share one definition.
func (u *URLs) Check(path, expParam, sigParam string) bool {
	exp, err := strconv.ParseInt(expParam, 10, 64)
	if err != nil || u.now().Unix() > exp {
		return false
	}
	got, err := hex.DecodeString(sigParam)
	if err != nil {
		return false
	}
	want, err := u.tag(path, exp)
	return err == nil && hmac.Equal(got, want)
}
