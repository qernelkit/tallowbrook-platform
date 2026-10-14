package mail

import (
	"strings"
	"testing"
)

func TestFooterFallsBackToEnglish(t *testing.T) {
	if got := Footer("sv").Locale; got != "en" {
		t.Errorf("locale = %q", got)
	}
	if got := Footer("de").Locale; got != "de" {
		t.Errorf("locale = %q", got)
	}
}

func TestRender(t *testing.T) {
	f := Footer("nl")
	f.Unsubscribe = "https://id.tallowbrook.example/prefs"
	out, err := f.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Het Tallowbrook Identity-team", "help.tallowbrook.example/nl", "Stop these emails"} {
		if !strings.Contains(out, want) {
			t.Errorf("footer missing %q:\n%s", want, out)
		}
	}
}
