package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		fwd    string
		want   string
	}{
		{"direct", "192.0.2.10:51000", "", "192.0.2.10"},
		{"forwarded", "10.0.0.1:443", "198.51.100.7", "198.51.100.7"},
		{"forwarded chain", "10.0.0.1:443", "198.51.100.7, 10.0.0.2", "198.51.100.7"},
		{"no port", "192.0.2.10", "", "192.0.2.10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			if tt.fwd != "" {
				r.Header.Set("X-Forwarded-For", tt.fwd)
			}
			if got := ClientIP(r); got != tt.want {
				t.Errorf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	l := NewRateLimiter(60, 3)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d refused inside the burst", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("fourth request allowed")
	}
	if !l.Allow("b") {
		t.Fatal("other key limited")
	}
	now = now.Add(2 * time.Second)
	if !l.Allow("a") {
		t.Fatal("bucket did not refill")
	}
}

func TestWriteError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantTitle  string
	}{
		{"known", ErrNotFound, http.StatusNotFound, "Not found"},
		{"bad request", BadRequest("missing field"), http.StatusBadRequest, "Bad request"},
		{"unknown", errors.New("database exploded"), http.StatusInternalServerError, "Internal error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			WriteError(w, httptest.NewRequest(http.MethodGet, "/", nil), tt.err)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d", w.Code)
			}
			var p Problem
			if err := json.NewDecoder(w.Body).Decode(&p); err != nil {
				t.Fatal(err)
			}
			if p.Title != tt.wantTitle {
				t.Errorf("title = %q", p.Title)
			}
			if strings.Contains(p.Detail, "database") {
				t.Error("internal error detail leaked")
			}
		})
	}
}

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	var v struct {
		Name string `json:"name"`
	}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a","admin":true}`))
	if err := DecodeJSON(r, 1024, &v); err == nil {
		t.Fatal("unknown field accepted")
	}
	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a"}`))
	if err := DecodeJSON(r, 1024, &v); err != nil || v.Name != "a" {
		t.Fatalf("got %q, %v", v.Name, err)
	}
}

func TestRequestIDPropagates(t *testing.T) {
	var seen string
	h := WithRequestID(slog.Default(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-ID", "req-123")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != "req-123" {
		t.Errorf("request id = %q", seen)
	}
}

func TestRecover(t *testing.T) {
	h := Recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", w.Code)
	}
}
