package accesspolicy

import "testing"

func TestLex(t *testing.T) {
	toks, err := Lex("(dept: ops) and (region: eu)")
	if err != nil {
		t.Fatal(err)
	}
	want := []Kind{KindLParen, KindIdent, KindColon, KindIdent, KindRParen, KindAnd, KindLParen, KindIdent, KindColon, KindIdent, KindRParen}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens: %v", len(toks), toks)
	}
	for i, k := range want {
		if toks[i].Kind != k {
			t.Errorf("token %d = %s, want %s", i, toks[i].Kind, k)
		}
	}
}

func TestLexErrors(t *testing.T) {
	for _, src := range []string{
		"(dept: ops",
		"dept: ops)",
		"dept = ops",
		"(dept: ops) && (region: eu)",
	} {
		if _, err := Lex(src); err == nil {
			t.Errorf("Lex(%q) accepted", src)
		}
	}
}

func TestNormalise(t *testing.T) {
	tests := map[string]string{
		"(dept:ops) and (region:eu)":         "(dept: ops) and (region: eu)",
		"  (dept: ops)   or   not (temp: y)": "(dept: ops) or not (temp: y)",
	}
	for in, want := range tests {
		toks, err := Lex(in)
		if err != nil {
			t.Fatalf("Lex(%q): %v", in, err)
		}
		if got := Normalise(toks); got != want {
			t.Errorf("Normalise(%q) = %q, want %q", in, got, want)
		}
	}
}
