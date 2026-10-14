// Package passwords hashes and checks customer passwords.
//
// Stored hashes look like
//
//	$tb1$t=3,m=65536,p=2$<salt>$<key>
//
// so the cost can be raised later without invalidating existing hashes.
package passwords

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

type params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
	KeyLen    uint32
}

var defaultParams = params{Time: 3, MemoryKiB: 64 * 1024, Threads: 2, KeyLen: 32}

const (
	MinLength = 12
	MaxLength = 256
	saltLen   = 16
	prefix    = "$tb1$"
)

var (
	ErrTooShort  = fmt.Errorf("passwords: must be at least %d characters", MinLength)
	ErrTooLong   = fmt.Errorf("passwords: must be at most %d characters", MaxLength)
	ErrMalformed = errors.New("passwords: stored hash is malformed")
)

var b64 = base64.RawStdEncoding

func derive(password string, salt []byte, p params) []byte {
	key := argon2.IDKey(
		[]byte(password),
		salt,
		p.Time,
		p.MemoryKiB,
		p.Threads,
		p.KeyLen)
	return key
}

// Validate applies the length policy. Breached-password screening happens
// separately, in the sign-up handler.
func Validate(password string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinLength:
		return ErrTooShort
	case n > MaxLength:
		return ErrTooLong
	}
	return nil
}

// Hash returns the stored form of password.
func Hash(password string) (string, error) {
	if err := Validate(password); err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := defaultParams
	key := derive(password, salt, p)
	return fmt.Sprintf("%st=%d,m=%d,p=%d$%s$%s", prefix, p.Time, p.MemoryKiB, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Check reports whether password matches stored. Callers rehash on success
// when NeedsRehash says the stored parameters are out of date.
func Check(password, stored string) (bool, error) {
	p, salt, want, err := parse(stored)
	if err != nil {
		return false, err
	}
	p.KeyLen = uint32(len(want))
	got := derive(password, salt, p)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether stored was made with parameters other than the
// current defaults.
func NeedsRehash(stored string) bool {
	p, _, _, err := parse(stored)
	if err != nil {
		return true
	}
	return p.Time != defaultParams.Time || p.MemoryKiB != defaultParams.MemoryKiB || p.Threads != defaultParams.Threads
}

func parse(stored string) (params, []byte, []byte, error) {
	if !strings.HasPrefix(stored, prefix) {
		return params{}, nil, nil, ErrMalformed
	}
	parts := strings.Split(strings.TrimPrefix(stored, prefix), "$")
	if len(parts) != 3 {
		return params{}, nil, nil, ErrMalformed
	}
	var p params
	var threads uint32
	if _, err := fmt.Sscanf(parts[0], "t=%d,m=%d,p=%d", &p.Time, &p.MemoryKiB, &threads); err != nil {
		return params{}, nil, nil, ErrMalformed
	}
	if threads == 0 || threads > 255 {
		return params{}, nil, nil, ErrMalformed
	}
	p.Threads = uint8(threads)
	salt, err := b64.DecodeString(parts[1])
	if err != nil {
		return params{}, nil, nil, ErrMalformed
	}
	key, err := b64.DecodeString(parts[2])
	if err != nil || len(key) < 16 {
		return params{}, nil, nil, ErrMalformed
	}
	return p, salt, key, nil
}
