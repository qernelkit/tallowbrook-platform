package passwords

import (
	"errors"
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

// Break-glass admin entries let on-call engineers reach the edge admin pages
// when the IdP itself is down. `idp admin htpasswd <user>` prints the line ops
// add to the edge's htpasswd file; nothing in this service reads it back.

const breakGlassCost = 13

var breakGlassUser = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)

// HtpasswdLine returns "user:hash" for the edge's htpasswd file.
func HtpasswdLine(user, password string) (string, error) {
	if !breakGlassUser.MatchString(user) {
		return "", errors.New("passwords: break-glass user must be 3-32 lowercase characters")
	}
	if len(password) < 24 {
		return "", errors.New("passwords: break-glass password must be at least 24 characters")
	}
	if len(password) > 72 {
		return "", errors.New("passwords: break-glass password must be at most 72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), breakGlassCost)
	if err != nil {
		return "", err
	}
	return user + ":" + string(hash), nil
}
