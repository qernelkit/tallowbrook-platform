package session

import (
	"testing"
	"time"
)

func TestExpired(t *testing.T) {
	now := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	s := Session{ExpiresAt: now}
	if !s.Expired(now) {
		t.Error("session valid at its expiry instant")
	}
	if s.Expired(now.Add(-time.Second)) {
		t.Error("session expired early")
	}
}

func TestStepUpRequired(t *testing.T) {
	now := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		s    Session
		want bool
	}{
		{"fresh workforce", Session{Realm: RealmWorkforce, IssuedAt: now.Add(-10 * time.Minute)}, false},
		{"old workforce", Session{Realm: RealmWorkforce, IssuedAt: now.Add(-2 * time.Hour)}, true},
		{"customer with hardware key", Session{Realm: RealmCustomer, AuthMethods: []string{"hwk"}}, false},
		{"customer with password", Session{Realm: RealmCustomer, AuthMethods: []string{"pwd"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.StepUpRequired(now); got != tt.want {
				t.Errorf("StepUpRequired = %v, want %v", got, tt.want)
			}
		})
	}
}
