// Package branding holds per-tenant colours and logos for the sign-in pages.
package branding

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

// Theme is a tenant's sign-in page theme.
type Theme struct {
	TenantID   string `json:"tenant_id"`
	Primary    string `json:"primary"`
	Accent     string `json:"accent"`
	Background string `json:"background"`
	LogoURL    string `json:"logo_url"`
}

// Default is used for tenants without a theme.
var Default = Theme{Primary: "#1d4e89", Accent: "#e07a1f", Background: "#ffffff"}

// rgb parses "#rrggbb".
func rgb(color string) ([3]byte, error) {
	var out [3]byte
	if len(color) != 7 || color[0] != '#' {
		return out, fmt.Errorf("branding: %q is not #rrggbb", color)
	}
	rgb, err := hex.DecodeString(strings.TrimPrefix(color, "#"))
	if err != nil {
		return out, fmt.Errorf("branding: %q is not #rrggbb", color)
	}
	copy(out[:], rgb)
	return out, nil
}

// luminance is the WCAG relative luminance, in 0..1.
func luminance(c [3]byte) float64 {
	ch := func(v byte) float64 {
		s := float64(v) / 255
		if s <= 0.03928 {
			return s / 12.92
		}
		return math.Pow((s+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(c[0]) + 0.7152*ch(c[1]) + 0.0722*ch(c[2])
}

// Validate checks that text on the primary colour is readable (contrast at
// least 4.5:1 against white).
func (t Theme) Validate() error {
	for _, c := range []string{t.Primary, t.Accent, t.Background} {
		if _, err := rgb(c); err != nil {
			return err
		}
	}
	p, _ := rgb(t.Primary)
	contrast := (1.05) / (luminance(p) + 0.05)
	if contrast < 4.5 {
		return fmt.Errorf("branding: primary colour %s is too light for white text (%.1f:1)", t.Primary, contrast)
	}
	return nil
}
