package tokenize

import (
	"errors"
	"strings"

	"github.com/capitalone/fpe/ff1"
)

// Account numbers are 12 digits, the last of which is a Luhn check digit.
// Tokens keep that shape (including a valid check digit), so the downstream
// payout systems accept them unchanged.

var (
	ErrFormat     = errors.New("tokenize: account numbers are 12 digits")
	ErrCheckDigit = errors.New("tokenize: check digit does not match")
	errKeySize    = errors.New("tokenize: key must be 32 bytes")
)

// transform is the part of the cipher the tokenizer uses.
type transform interface {
	Encrypt(x string) (string, error)
	Decrypt(x string) (string, error)
}

// Tokenizer turns account numbers into tokens and back.
type Tokenizer struct {
	key []byte
}

func NewTokenizer(key []byte) (*Tokenizer, error) {
	if len(key) != 32 {
		return nil, errKeySize
	}
	return &Tokenizer{key: key}, nil
}

// prepare validates a 12-digit value and returns a cipher and its 11 payload digits.
func (t *Tokenizer) prepare(number string) (transform, string, error) {
	if len(number) != 12 || strings.Trim(number, "0123456789") != "" {
		return nil, "", ErrFormat
	}
	if !luhnValid(number) {
		return nil, "", ErrCheckDigit
	}
	c, err := ff1.NewCipher(10, 12, t.key, nil)
	if err != nil {
		return nil, "", err
	}
	return c, number[:11], nil
}

// Tokenize returns the token for an account number.
func (t *Tokenizer) Tokenize(number string) (string, error) {
	c, payload, err := t.prepare(number)
	if err != nil {
		return "", err
	}
	out, err := c.Encrypt(payload)
	if err != nil {
		return "", err
	}
	return out + luhnDigit(out), nil
}

// Detokenize returns the account number behind a token.
func (t *Tokenizer) Detokenize(token string) (string, error) {
	c, payload, err := t.prepare(token)
	if err != nil {
		return "", err
	}
	out, err := c.Decrypt(payload)
	if err != nil {
		return "", err
	}
	return out + luhnDigit(out), nil
}

func luhnValid(number string) bool {
	return luhnDigit(number[:len(number)-1]) == number[len(number)-1:]
}

// luhnDigit returns the check digit for payload.
func luhnDigit(payload string) string {
	sum := 0
	double := true
	for i := len(payload) - 1; i >= 0; i-- {
		d := int(payload[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return string(rune('0' + (10-sum%10)%10))
}
