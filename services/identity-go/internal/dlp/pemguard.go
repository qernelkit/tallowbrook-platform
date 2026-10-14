// Package dlp stops support-ticket attachments from carrying key material.
// Customers sometimes paste whole config files into tickets; the guard rejects
// uploads that look like they contain a private key so they never reach the
// ticketing vendor.
package dlp

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
)

const rsaPrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----"

var pemBlockPattern = regexp.MustCompile(`-----BEGIN [A-Z ]+-----`)

// ErrKeyMaterial is returned for attachments that must not be uploaded.
var ErrKeyMaterial = errors.New("dlp: attachment looks like it contains a private key; remove it and try again")

// CheckAttachment inspects an uploaded file.
func CheckAttachment(name string, body []byte) error {
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte(rsaPrivateKeyHeader)) {
		return ErrKeyMaterial
	}
	for _, m := range pemBlockPattern.FindAll(body, -1) {
		if bytes.Contains(m, []byte("PRIVATE")) {
			return ErrKeyMaterial
		}
	}
	lower := strings.ToLower(name)
	for _, ext := range []string{".p12", ".pfx", ".jks", ".ppk"} {
		if strings.HasSuffix(lower, ext) {
			return ErrKeyMaterial
		}
	}
	return nil
}

// ArmourHeaders counts armour headers in pasted ticket text, for the
// weekly report to the support leads.
func ArmourHeaders(text string) int {
	return len(pemBlockPattern.FindAllString(text, -1))
}
