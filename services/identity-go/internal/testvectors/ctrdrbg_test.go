package testvectors

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var goldenSeed = mustHex("f5bed294e3a021da248fdb7a2e84c3077e8537d84cf1f381777a16935c510a3b67eb1e2ec2a7d664bf89d90ac7ddc594")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// wantGolden is the recorded output of the two reads below. Cookie codec
// fixtures are cut from these bytes, so a change here means re-recording them.
const wantGolden = "8ecdeadaeaf6ab7c3e3ab3743181c6feb9888ccc21a0b4502491df3cf10dd484" +
	"df4a05d0d8344abfa1bf458e3741100e5eaec2a359b0ba15"

func TestGoldenCookieBytes(t *testing.T) {
	d, err := NewCTRDRBG(goldenSeed, []byte("session cookie golden v1"))
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 32)
	second := make([]byte, 24)
	if _, err := d.Read(first); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Read(second); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(append(first, second...)); got != wantGolden {
		t.Errorf("output = %s\nwant     %s", got, wantGolden)
	}
}

func TestSameSeedSameBytes(t *testing.T) {
	a, _ := NewCTRDRBG(goldenSeed, nil)
	b, _ := NewCTRDRBG(goldenSeed, nil)
	x := make([]byte, 100)
	y := make([]byte, 100)
	a.Read(x)
	b.Read(y)
	if !bytes.Equal(x, y) {
		t.Fatal("two generators with one seed diverged")
	}
}

func TestPersonalizationChangesOutput(t *testing.T) {
	a, _ := NewCTRDRBG(goldenSeed, []byte("a"))
	b, _ := NewCTRDRBG(goldenSeed, []byte("b"))
	x := make([]byte, 32)
	y := make([]byte, 32)
	a.Read(x)
	b.Read(y)
	if bytes.Equal(x, y) {
		t.Fatal("personalization had no effect")
	}
}

func TestRejectsBadSeed(t *testing.T) {
	tests := []struct {
		name   string
		seed   []byte
		person []byte
	}{
		{"short", make([]byte, 47), nil},
		{"long", make([]byte, 49), nil},
		{"personalization too long", make([]byte, 48), make([]byte, 49)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewCTRDRBG(tt.seed, tt.person); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
