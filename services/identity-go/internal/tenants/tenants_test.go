package tenants

import (
	"context"
	"errors"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		t    Tenant
		want error
	}{
		{"ok", Tenant{Slug: "pellworth-freight", Plan: PlanBusiness, Domains: []string{"pellworth.example"}}, nil},
		{"short slug", Tenant{Slug: "pf", Plan: PlanBusiness}, ErrSlug},
		{"upper case slug", Tenant{Slug: "Pellworth", Plan: PlanBusiness}, ErrSlug},
		{"trailing dash", Tenant{Slug: "pellworth-", Plan: PlanBusiness}, ErrSlug},
		{"unknown plan", Tenant{Slug: "pellworth", Plan: "gold"}, ErrPlan},
		{"bad domain", Tenant{Slug: "pellworth", Plan: PlanStarter, Domains: []string{"-bad.example"}}, ErrDomain},
		{"single label", Tenant{Slug: "pellworth", Plan: PlanStarter, Domains: []string{"localhost"}}, ErrDomain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.t.Validate(); !errors.Is(got, tt.want) {
				t.Errorf("Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOwnsEmail(t *testing.T) {
	tn := Tenant{Domains: []string{"pellworth.example"}}
	tests := map[string]bool{
		"ops@pellworth.example":         true,
		"ops@EU.Pellworth.example":      true,
		"ops@notpellworth.example":      false,
		"ops@pellworth.example.evil":    false,
		"not-an-address":                false,
		"pellworth.example@example.com": false,
	}
	for email, want := range tests {
		if got := tn.OwnsEmail(email); got != want {
			t.Errorf("OwnsEmail(%q) = %v, want %v", email, got, want)
		}
	}
}

func TestUserLimit(t *testing.T) {
	for _, tt := range []struct {
		plan Plan
		want int
	}{{PlanStarter, 50}, {PlanBusiness, 1000}, {PlanEnterprise, 100000}} {
		if got, err := UserLimit(tt.plan); err != nil || got != tt.want {
			t.Errorf("UserLimit(%s) = %d, %v", tt.plan, got, err)
		}
	}
}

func TestStore(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	tn := &Tenant{Name: "Pellworth Freight", Slug: "pellworth", Plan: PlanBusiness}
	if err := s.Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if tn.MaxUsers != 1000 {
		t.Errorf("MaxUsers = %d", tn.MaxUsers)
	}
	if err := s.Create(ctx, &Tenant{Name: "Other", Slug: "pellworth", Plan: PlanStarter}); !errors.Is(err, ErrTaken) {
		t.Fatalf("duplicate slug: %v", err)
	}
	got, err := s.BySlug(ctx, "pellworth")
	if err != nil || got.ID != tn.ID {
		t.Fatalf("BySlug = %+v, %v", got, err)
	}
	if err := s.Suspend(ctx, tn.ID, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, tn.ID); !got.Suspended {
		t.Error("suspend did not stick")
	}
	if _, err := s.LoadKey(ctx, tn.ID); err == nil {
		t.Error("key returned for a tenant without one")
	}
	blob := []byte(t.Name())
	if err := s.SaveKey(ctx, tn.ID, blob); err != nil {
		t.Fatal(err)
	}
	if k, err := s.LoadKey(ctx, tn.ID); err != nil || string(k) != t.Name() {
		t.Fatalf("LoadKey = %q, %v", k, err)
	}
}
