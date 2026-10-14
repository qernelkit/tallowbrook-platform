package users

import (
	"context"
	"errors"
	"testing"
	"time"

	"tallowbrook.example/identity/internal/session"
)

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"Ana.Silva@Example.COM", "ana.silva@example.com", false},
		{"  bob@depot.tallowbrook.example ", "bob@depot.tallowbrook.example", false},
		{"Carla <carla@example.org>", "carla@example.org", false},
		{"no-at-sign", "", true},
		{"dave@localhost", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		got, err := NormalizeEmail(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("NormalizeEmail(%q) err = %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestValidateProfile(t *testing.T) {
	long := make([]rune, 101)
	for i := range long {
		long[i] = 'x'
	}
	tests := []struct {
		name, locale string
		want         error
	}{
		{"Ana Silva", "en", nil},
		{"Zoë", "", nil},
		{"   ", "en", ErrInvalidName},
		{string(long), "en", ErrInvalidName},
		{"Ana", "pt", ErrLocale},
	}
	for _, tt := range tests {
		if got := ValidateProfile(tt.name, tt.locale); !errors.Is(got, tt.want) {
			t.Errorf("ValidateProfile(%q, %q) = %v, want %v", tt.name, tt.locale, got, tt.want)
		}
	}
}

func TestLockout(t *testing.T) {
	now := time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC)
	u := &User{Status: StatusActive}
	for i := 0; i < 4; i++ {
		u.RecordFailure(now)
	}
	if u.Locked(now) {
		t.Fatal("locked after four failures")
	}
	u.RecordFailure(now)
	if !u.Locked(now) {
		t.Fatal("not locked after five failures")
	}
	if u.Locked(now.Add(16 * time.Minute)) {
		t.Fatal("still locked after the lockout period")
	}
	u.RecordSuccess()
	if u.Status != StatusActive || u.FailedLogins != 0 {
		t.Fatalf("after success: %+v", u)
	}
}

func TestSafeReturn(t *testing.T) {
	tests := map[string]string{
		"":                           "/",
		"/account":                   "/account",
		"/authorize?client_id=x":     "/authorize?client_id=x",
		"//evil.example/":            "/",
		"https://evil.example/":      "/",
		"javascript:alert(1)":        "/",
		"account":                    "/",
		"/\\evil.example":            "/",
		"/signin?return_to=%2Fhome":  "/signin?return_to=%2Fhome",
		"http://id.tallowbrook.test": "/",
	}
	for in, want := range tests {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStoreCreateAndLookup(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	u := &User{TenantID: "t_1", Realm: session.RealmCustomer, Email: "ana@example.com", Name: "Ana", Status: StatusActive}
	if err := s.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if u.ID == "" {
		t.Fatal("no id assigned")
	}
	if err := s.Create(ctx, &User{TenantID: "t_1", Email: "ana@example.com"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := s.Create(ctx, &User{TenantID: "t_2", Email: "ana@example.com"}); err != nil {
		t.Fatalf("same email, other tenant: %v", err)
	}
	got, err := s.ByEmail(ctx, "t_1", "ana@example.com")
	if err != nil || got.ID != u.ID {
		t.Fatalf("ByEmail = %+v, %v", got, err)
	}
	if _, err := s.Get(ctx, "u_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestStoreUpdateMovesEmailIndex(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	u := &User{TenantID: "t_1", Email: "old@example.com"}
	if err := s.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	_, err := s.Update(ctx, u.ID, func(x *User) error { x.Email = "new@example.com"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ByEmail(ctx, "t_1", "old@example.com"); !errors.Is(err, ErrNotFound) {
		t.Error("old address still indexed")
	}
	if _, err := s.ByEmail(ctx, "t_1", "new@example.com"); err != nil {
		t.Error("new address not indexed")
	}
}

func TestListTenantPages(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	for _, e := range []string{"c@example.com", "a@example.com", "b@example.com", "d@example.com"} {
		if err := s.Create(ctx, &User{TenantID: "t_1", Email: e}); err != nil {
			t.Fatal(err)
		}
	}
	page := s.ListTenant(ctx, "t_1", 1, 2)
	if len(page) != 2 || page[0].Email != "b@example.com" || page[1].Email != "c@example.com" {
		t.Fatalf("page = %+v", page)
	}
	if got := s.ListTenant(ctx, "t_1", 10, 2); got != nil {
		t.Fatalf("past the end = %+v", got)
	}
}

func TestAccountHidesDisabledUsers(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	u := &User{TenantID: "t_1", Email: "gone@example.com", Status: StatusDisabled}
	if err := s.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Account(ctx, u.ID); err == nil {
		t.Fatal("disabled account returned")
	}
}
