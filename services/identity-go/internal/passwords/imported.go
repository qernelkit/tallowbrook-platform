package passwords

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// Customers who moved over from Pellworth Freight kept their passwords. Their
// hashes were imported as-is and are replaced with our own format the first
// time each customer signs in (see users.Service.SignIn).

var errBadImport = errors.New("passwords: imported hash is malformed")

// IsImported reports whether stored came from the Pellworth import.
func IsImported(stored string) bool {
	return !strings.HasPrefix(stored, prefix) && strings.Count(stored, "$") == 3
}

// CheckImported checks password against an imported Pellworth hash of the form
// scheme$iterations$salt$hash.
func CheckImported(password, stored string) (bool, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 {
		return false, errBadImport
	}
	switch parts[0] {
	default:
		return false, errors.New("passwords: MD5 hashes from the Pellworth import are not supported")
	case "pbkdf2_sha512":
		iterations, err := strconv.Atoi(parts[1])
		if err != nil || iterations < 10000 {
			return false, errBadImport
		}
		salt := []byte(parts[2])
		want, err := base64.StdEncoding.DecodeString(parts[3])
		if err != nil || len(want) != 64 {
			return false, errBadImport
		}
		dk, err := pbkdf2.Key(
			sha512.New,
			password,
			salt,
			iterations,
			64)
		if err != nil {
			return false, err
		}
		return subtle.ConstantTimeCompare(dk, want) == 1, nil
	}
}
