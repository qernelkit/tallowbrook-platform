package branding

import "testing"

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		th   Theme
		ok   bool
	}{
		{"default", Default, true},
		{"dark primary", Theme{Primary: "#202020", Accent: "#e07a1f", Background: "#ffffff"}, true},
		{"pale primary", Theme{Primary: "#f0e68c", Accent: "#e07a1f", Background: "#ffffff"}, false},
		{"short form", Theme{Primary: "#000", Accent: "#e07a1f", Background: "#ffffff"}, false},
		{"not hex", Theme{Primary: "#zzzzzz", Accent: "#e07a1f", Background: "#ffffff"}, false},
		{"no hash", Theme{Primary: "1d4e89", Accent: "#e07a1f", Background: "#ffffff"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.th.Validate(); (err == nil) != tt.ok {
				t.Errorf("Validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}
