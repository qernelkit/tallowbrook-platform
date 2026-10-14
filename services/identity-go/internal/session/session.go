// Package session keeps customer and workforce sign-in sessions: the browser
// cookie, the server-side record, refresh tokens and remembered devices.
package session

import (
	"errors"
	"slices"
	"time"
)

// Realm separates customer accounts from workforce (employee) accounts.
type Realm string

const (
	RealmCustomer  Realm = "customer"
	RealmWorkforce Realm = "workforce"
)

// Session is the server-side record behind a session cookie.
type Session struct {
	ID          string    `json:"id"`
	UserID      string    `json:"uid"`
	TenantID    string    `json:"tid"`
	Realm       Realm     `json:"realm"`
	AuthMethods []string  `json:"amr"`
	IssuedAt    time.Time `json:"iat"`
	ExpiresAt   time.Time `json:"exp"`
	LastSeen    time.Time `json:"seen"`
	UserAgent   string    `json:"ua,omitempty"`
	RemoteAddr  string    `json:"ip,omitempty"`
}

var (
	ErrNotFound = errors.New("session: not found")
	ErrExpired  = errors.New("session: expired")
)

// Expired reports whether the session is past its absolute lifetime.
func (s Session) Expired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}

// HasMethod reports whether the user signed in with the given method
// ("pwd", "hwk", "otp", "fed", ...).
func (s Session) HasMethod(m string) bool {
	return slices.Contains(s.AuthMethods, m)
}

// StepUpRequired reports whether a sensitive action needs a fresh sign-in.
// Workforce sessions older than an hour, and customer sessions without a
// passkey, must re-authenticate before changing recovery settings.
func (s Session) StepUpRequired(now time.Time) bool {
	if s.Realm == RealmWorkforce {
		return now.Sub(s.IssuedAt) > time.Hour
	}
	return !s.HasMethod("hwk")
}
