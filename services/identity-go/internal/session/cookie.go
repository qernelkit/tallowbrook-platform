package session

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const cookieName = "__Host-tb_session"

var errMalformedCookie = errors.New("session: malformed cookie")

// cookieClaims is what travels in the browser; the rest stays server-side.
type cookieClaims struct {
	SessionID string    `json:"sid"`
	Realm     Realm     `json:"r"`
	Expires   time.Time `json:"e"`
}

// CookieCodec seals session references into the browser cookie.
type CookieCodec struct {
	aead   cipher.AEAD
	secure bool
}

// cookieEncoding keeps cookie values URL-safe and without padding.
var cookieEncoding = base64.RawURLEncoding

func NewCookieCodec(key []byte, secure bool) (*CookieCodec, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &CookieCodec{aead: aead, secure: secure}, nil
}

// Write sets the session cookie for s.
func (c *CookieCodec) Write(w http.ResponseWriter, s Session) error {
	payload, err := json.Marshal(cookieClaims{SessionID: s.ID, Realm: s.Realm, Expires: s.ExpiresAt})
	if err != nil {
		return err
	}
	nonce := make([]byte, c.aead.NonceSize(), c.aead.NonceSize()+len(payload)+c.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := c.aead.Seal(nonce, nonce, payload, []byte(cookieName))
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    cookieEncoding.EncodeToString(sealed),
		Path:     "/",
		Expires:  s.ExpiresAt,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Read returns the session reference carried by the request, if any.
func (c *CookieCodec) Read(r *http.Request, now time.Time) (string, Realm, error) {
	ck, err := r.Cookie(cookieName)
	if err != nil {
		return "", "", ErrNotFound
	}
	raw, err := cookieEncoding.DecodeString(ck.Value)
	if err != nil || len(raw) < c.aead.NonceSize() {
		return "", "", errMalformedCookie
	}
	n := c.aead.NonceSize()
	payload, err := c.aead.Open(nil, raw[:n], raw[n:], []byte(cookieName))
	if err != nil {
		return "", "", errMalformedCookie
	}
	var claims cookieClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", errMalformedCookie
	}
	if !now.Before(claims.Expires) {
		return "", "", ErrExpired
	}
	return claims.SessionID, claims.Realm, nil
}

// Clear removes the session cookie.
func (c *CookieCodec) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
}
