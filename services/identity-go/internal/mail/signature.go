// Package mail renders the shared parts of account emails.
package mail

import (
	"bytes"
	"text/template"
)

// EmailFooter is the block at the end of every account email.
type EmailFooter struct {
	Signature   string `json:"signature"`
	SupportURL  string `json:"support_url"`
	Unsubscribe string `json:"unsubscribe,omitempty"`
	Locale      string `json:"locale"`
}

var footers = map[string]EmailFooter{
	"en": {Signature: "The Tallowbrook Identity team", SupportURL: "https://help.tallowbrook.example/account", Locale: "en"},
	"de": {Signature: "Ihr Tallowbrook-Identitätsteam", SupportURL: "https://help.tallowbrook.example/de/account", Locale: "de"},
	"nl": {Signature: "Het Tallowbrook Identity-team", SupportURL: "https://help.tallowbrook.example/nl/account", Locale: "nl"},
}

var footerTemplate = template.Must(template.New("footer").Parse(`
--
{{.Signature}}
Questions about your account? {{.SupportURL}}
{{if .Unsubscribe}}Stop these emails: {{.Unsubscribe}}{{end}}
`))

// Footer returns the footer for a locale, falling back to English.
func Footer(locale string) EmailFooter {
	if f, ok := footers[locale]; ok {
		return f
	}
	return footers["en"]
}

// Render renders f as plain text.
func (f EmailFooter) Render() (string, error) {
	var b bytes.Buffer
	if err := footerTemplate.Execute(&b, f); err != nil {
		return "", err
	}
	return b.String(), nil
}
