package config

import (
	"reflect"
	"testing"
	"time"
)

func TestSplitList(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b", []string{"a", "b"}},
		{" a , b ,, c ", []string{"a", "b", "c"}},
		{",,,", nil},
	}
	for _, tt := range tests {
		if got := splitList(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitList(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDurationEnv(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{"unset uses default", "", 5 * time.Minute, false},
		{"minutes", "15m", 15 * time.Minute, false},
		{"hours", "36h", 36 * time.Hour, false},
		{"garbage", "soon", 0, true},
		{"negative", "-1h", 0, true},
		{"zero", "0s", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TEST_DURATION", tt.value)
			got, err := durationEnv("TEST_DURATION", 5*time.Minute)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestIntEnv(t *testing.T) {
	t.Setenv("TEST_INT", "")
	if n, err := intEnv("TEST_INT", 16); err != nil || n != 16 {
		t.Fatalf("default: got %d, %v", n, err)
	}
	t.Setenv("TEST_INT", "32")
	if n, err := intEnv("TEST_INT", 16); err != nil || n != 32 {
		t.Fatalf("set: got %d, %v", n, err)
	}
	for _, bad := range []string{"0", "-4", "many"} {
		t.Setenv("TEST_INT", bad)
		if _, err := intEnv("TEST_INT", 16); err == nil {
			t.Errorf("intEnv accepted %q", bad)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("IDP_LISTEN_ADDR", "")
	t.Setenv("IDP_EXPERIMENTS", "breach-check, anon-login")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q", c.ListenAddr)
	}
	if c.SessionShards != 16 {
		t.Errorf("SessionShards = %d", c.SessionShards)
	}
	if !c.Enabled("anon-login") || c.Enabled("sealed-exports") {
		t.Errorf("Experiments = %q", c.Experiments)
	}
}
