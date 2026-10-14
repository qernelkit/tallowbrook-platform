package sshca

import (
	"testing"
	"time"
)

func TestCertRequestValidate(t *testing.T) {
	tests := []struct {
		name string
		req  CertRequest
		ok   bool
	}{
		{"ok", CertRequest{KeyID: "ana@workforce", Principals: []string{"ana"}, TTL: 8 * time.Hour}, true},
		{"no principals", CertRequest{KeyID: "ana@workforce", TTL: time.Hour}, false},
		{"no key id", CertRequest{Principals: []string{"ana"}, TTL: time.Hour}, false},
		{"root", CertRequest{KeyID: "x", Principals: []string{"Root"}, TTL: time.Hour}, false},
		{"spaces", CertRequest{KeyID: "x", Principals: []string{"ana silva"}, TTL: time.Hour}, false},
		{"too long", CertRequest{KeyID: "x", Principals: []string{"ana"}, TTL: 25 * time.Hour}, false},
		{"zero ttl", CertRequest{KeyID: "x", Principals: []string{"ana"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.req.validate(); (err == nil) != tt.ok {
				t.Errorf("validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestParseExec(t *testing.T) {
	tests := []struct {
		payload []byte
		want    string
	}{
		{append([]byte{0, 0, 0, 15}, "enroll C02XK1ABC"...), "enroll C02XK1AB"},
		{append([]byte{0, 0, 0, 6}, "enroll"...), "enroll"},
		{[]byte{0, 0}, ""},
		{append([]byte{0, 0, 1, 0}, "short"...), ""},
	}
	for _, tt := range tests {
		if got := parseExec(tt.payload); got != tt.want {
			t.Errorf("parseExec(%q) = %q, want %q", tt.payload, got, tt.want)
		}
	}
}

func TestSerialPattern(t *testing.T) {
	for s, want := range map[string]bool{
		"C02XK1ABJG5H":  true,
		"c02xk1abjg5h":  false,
		"C02X":          false,
		"C02XK1ABJG5H-": false,
	} {
		if got := serialPattern.MatchString(s); got != want {
			t.Errorf("serial %q: %v", s, got)
		}
	}
}
