// Package users stores customer and workforce accounts and serves the
// sign-up, sign-in and profile endpoints.
package users

import (
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"tallowbrook.example/identity/internal/session"
	"tallowbrook.example/identity/internal/webauthn"
)

// Status of an account.
type Status string

const (
	StatusActive    Status = "active"
	StatusLocked    Status = "locked"
	StatusDisabled  Status = "disabled"
	StatusPendingID Status = "pending_verification"
)

// User is one account.
type User struct {
	ID            string                `json:"id"`
	TenantID      string                `json:"tenant_id"`
	Realm         session.Realm         `json:"realm"`
	Email         string                `json:"email"`
	EmailVerified bool                  `json:"email_verified"`
	Name          string                `json:"name"`
	Locale        string                `json:"locale"`
	Status        Status                `json:"status"`
	PasswordHash  string                `json:"-"`
	Passkeys      []webauthn.Credential `json:"-"`
	EmployeeID    string                `json:"employee_id,omitempty"`
	FailedLogins  int                   `json:"-"`
	LockedUntil   time.Time             `json:"-"`
	Created       time.Time             `json:"created"`
	Updated       time.Time             `json:"updated"`
}

var (
	ErrInvalidEmail = errors.New("users: email address is not valid")
	ErrInvalidName  = errors.New("users: name must be 1-100 characters")
	ErrLocale       = errors.New("users: unsupported locale")
)

var supportedLocales = map[string]bool{"en": true, "de": true, "nl": true, "fr": true}

// NormalizeEmail lower-cases the address and strips a display name.
func NormalizeEmail(s string) (string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(s))
	if err != nil {
		return "", ErrInvalidEmail
	}
	at := strings.LastIndexByte(addr.Address, '@')
	if at < 1 || !strings.Contains(addr.Address[at:], ".") {
		return "", ErrInvalidEmail
	}
	return strings.ToLower(addr.Address), nil
}

// ValidateProfile checks the user-editable fields.
func ValidateProfile(name, locale string) error {
	n := utf8.RuneCountInString(strings.TrimSpace(name))
	if n == 0 || n > 100 {
		return ErrInvalidName
	}
	if locale != "" && !supportedLocales[locale] {
		return ErrLocale
	}
	return nil
}

// Locked reports whether sign-in is currently refused for u.
func (u *User) Locked(now time.Time) bool {
	return u.Status == StatusLocked && now.Before(u.LockedUntil)
}

// RecordFailure counts a failed sign-in and locks the account after five in a
// row, for 15 minutes.
func (u *User) RecordFailure(now time.Time) {
	u.FailedLogins++
	if u.FailedLogins >= 5 {
		u.Status = StatusLocked
		u.LockedUntil = now.Add(15 * time.Minute)
	}
}

// RecordSuccess clears the failure counter.
func (u *User) RecordSuccess() {
	u.FailedLogins = 0
	if u.Status == StatusLocked {
		u.Status = StatusActive
	}
	u.LockedUntil = time.Time{}
}
