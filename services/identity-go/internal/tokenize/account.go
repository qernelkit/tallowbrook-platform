// Package tokenize replaces customer bank account numbers with tokens of the
// same shape, so support tools and exports never hold the real number.
package tokenize

import (
	"strings"
	"time"
)

// Account is a customer's payout account as the support console shows it.
type Account struct {
	ID         string
	CustomerID string
	Holder     string
	Token      string // tokenized account number
	Last4      string
	Added      time.Time
	Verified   bool
}

// EncryptedLabel is the masked form shown next to the token in the console.
func (a Account) EncryptedLabel() string {
	return "•••• " + a.Last4
}

// DisplayHolder shortens long holder names for list views.
func (a Account) DisplayHolder() string {
	name := strings.TrimSpace(a.Holder)
	if len([]rune(name)) <= 28 {
		return name
	}
	return string([]rune(name)[:27]) + "…"
}
