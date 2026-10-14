package tokenize

import "testing"

func TestLuhnDigit(t *testing.T) {
	tests := map[string]string{
		"7992739871": "3",
		"1234567890": "3",
		"0000000000": "0",
	}
	for payload, want := range tests {
		if got := luhnDigit(payload); got != want {
			t.Errorf("luhnDigit(%s) = %s, want %s", payload, got, want)
		}
	}
}

func TestLuhnValid(t *testing.T) {
	for n, want := range map[string]bool{
		"79927398713": true,
		"79927398710": false,
		"12345678903": true,
	} {
		if got := luhnValid(n); got != want {
			t.Errorf("luhnValid(%s) = %v", n, got)
		}
	}
}

func TestDisplayHolder(t *testing.T) {
	a := Account{Holder: "  Harborline Staffing Services Europe B.V.  "}
	if got := a.DisplayHolder(); len([]rune(got)) != 28 {
		t.Errorf("DisplayHolder = %q", got)
	}
	a.Holder = "Mira Okafor"
	if got := a.DisplayHolder(); got != "Mira Okafor" {
		t.Errorf("DisplayHolder = %q", got)
	}
}

func TestNewTokenizerChecksKeyLength(t *testing.T) {
	if _, err := NewTokenizer(make([]byte, 16)); err == nil {
		t.Fatal("16-byte key accepted")
	}
}
