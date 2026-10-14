package users

import (
	"context"
	"errors"
	"net/http"
	"time"

	"tallowbrook.example/identity/internal/federation"
	"tallowbrook.example/identity/internal/notify"
	"tallowbrook.example/identity/internal/session"
)

// WorkforceTenant is the tenant that holds employee accounts.
const WorkforceTenant = "t_tallowbrook"

const deviceCookie = "__Host-tb_device"

// SignInEmployee implements federation.Employees: it finds or creates the
// employee's workforce account and starts a workforce session.
func (s *Service) SignInEmployee(ctx context.Context, w http.ResponseWriter, r *http.Request, c *federation.UpstreamClaims) error {
	email, err := NormalizeEmail(c.Email)
	if err != nil {
		return err
	}
	u, err := s.Store.ByEmail(ctx, WorkforceTenant, email)
	if errors.Is(err, ErrNotFound) {
		u = User{
			TenantID:      WorkforceTenant,
			Realm:         session.RealmWorkforce,
			Email:         email,
			EmailVerified: true,
			Name:          c.Name,
			Locale:        "en",
			Status:        StatusActive,
			EmployeeID:    c.EmployeeID,
		}
		if err := s.Store.Create(ctx, &u); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if u.Status == StatusDisabled || u.EmployeeID != c.EmployeeID {
		return errors.New("users: workforce account does not match the upstream employee")
	}
	return s.startSession(w, r, u, []string{"fed"})
}

// noteDevice tells the user about sign-ins from devices we have not seen, and
// remembers this device for next time.
func (s *Service) noteDevice(ctx context.Context, w http.ResponseWriter, r *http.Request, u User) {
	if s.Devices == nil {
		return
	}
	now := s.Now()
	if ck, err := r.Cookie(deviceCookie); err == nil {
		if _, ok := s.Devices.Check(ck.Value, u.ID, now); ok {
			return
		}
	}
	mark := s.Devices.Issue(u.ID, "d"+now.Format("060102150405"), now)
	http.SetCookie(w, &http.Cookie{
		Name:     deviceCookie,
		Value:    mark,
		Path:     "/",
		Expires:  now.Add(30 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	err := s.Mail.Send(ctx, notify.Message{
		From:    "Tallowbrook <no-reply@tallowbrook.example>",
		To:      []string{u.Email},
		Subject: "New sign-in to your Tallowbrook account",
		Text:    "Your account was just used to sign in from a device we have not seen before (" + r.UserAgent() + ").\n\nIf this was not you, reset your password now.",
	})
	if err != nil {
		s.Log.Warn("new device email", "user", u.ID, "err", err)
	}
}
