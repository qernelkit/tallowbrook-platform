// Package cryptoutil formats identifiers and device fingerprints for logs and
// the admin console. It only formats bytes that other systems produced.
package cryptoutil

import (
	"encoding/hex"
	"strings"
)

// HexID renders a request or trace ID.
func HexID(b []byte) string {
	return hex.EncodeToString(b)
}

// ShortID returns the first eight hex characters of an ID, for log lines.
func ShortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// FormatFingerprint renders a device fingerprint that MDM reported, as
// colon-separated upper-case pairs: "AB:CD:...".
func FormatFingerprint(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}
