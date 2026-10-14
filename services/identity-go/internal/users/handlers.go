package users

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tallowbrook.example/identity/internal/httpx"
	"tallowbrook.example/identity/internal/magiclink"
	"tallowbrook.example/identity/internal/notify"
	"tallowbrook.example/identity/internal/passwords"
	"tallowbrook.example/identity/internal/session"
)

// Mailer sends account email.
type Mailer interface {
	Send(ctx context.Context, msg notify.Message) error
}

// Service serves the customer account endpoints.
type Service struct {
	Store      *Store
	Sessions   *session.Store
	Cookies    *session.CookieCodec
	Links      *magiclink.Links
	Devices    *session.DeviceMarker
	Mail       Mailer
	SessionTTL time.Duration
	Limiter    *httpx.RateLimiter
	Log        *slog.Logger
	Now        func() time.Time
}

// Routes registers the account endpoints.
func (s *Service) Routes(mux *http.ServeMux) {
	mux.Handle("POST /signup", s.Limiter.Limit(http.HandlerFunc(s.signup)))
	mux.Handle("POST /signin/password", s.Limiter.Limit(http.HandlerFunc(s.signinPassword)))
	mux.Handle("POST /signin/link", s.Limiter.Limit(http.HandlerFunc(s.requestLink)))
	mux.HandleFunc("GET /signin/link", s.redeemLink)
	mux.HandleFunc("GET /me", s.me)
	mux.HandleFunc("PATCH /me", s.updateMe)
}

type signupRequest struct {
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Locale   string `json:"locale"`
}

func (s *Service) signup(w http.ResponseWriter, r *http.Request) {
	var req signupRequest
	if err := httpx.DecodeJSON(r, 8<<10, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	email, err := NormalizeEmail(req.Email)
	if err != nil {
		httpx.WriteError(w, r, httpx.BadRequest(err.Error()))
		return
	}
	if err := ValidateProfile(req.Name, req.Locale); err != nil {
		httpx.WriteError(w, r, httpx.BadRequest(err.Error()))
		return
	}
	stored, err := passwords.Hash(req.Password)
	if err != nil {
		httpx.WriteError(w, r, httpx.BadRequest(err.Error()))
		return
	}
	u := &User{
		TenantID:     req.TenantID,
		Realm:        session.RealmCustomer,
		Email:        email,
		Name:         strings.TrimSpace(req.Name),
		Locale:       req.Locale,
		Status:       StatusPendingID,
		PasswordHash: stored,
	}
	if err := s.Store.Create(r.Context(), u); err != nil {
		if errors.Is(err, ErrDuplicate) {
			// Same answer as success, so sign-up cannot be used to probe for accounts.
			httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "check your email"})
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	s.sendLink(r.Context(), email, req.TenantID, "/welcome")
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "check your email"})
}

type passwordSignin struct {
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	ReturnTo string `json:"return_to"`
}

func (s *Service) signinPassword(w http.ResponseWriter, r *http.Request) {
	var req passwordSignin
	if err := httpx.DecodeJSON(r, 8<<10, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	email, err := NormalizeEmail(req.Email)
	if err != nil {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}
	u, err := s.Store.ByEmail(r.Context(), req.TenantID, email)
	if err != nil || u.Locked(s.Now()) || u.Status == StatusDisabled {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}
	ok, err := s.checkPassword(u, req.Password)
	if err != nil {
		s.Log.Warn("stored password unreadable", "user", u.ID, "err", err)
	}
	if !ok {
		_, _ = s.Store.Update(r.Context(), u.ID, func(x *User) error { x.RecordFailure(s.Now()); return nil })
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}
	u, err = s.Store.Update(r.Context(), u.ID, func(x *User) error {
		x.RecordSuccess()
		if passwords.IsImported(x.PasswordHash) || passwords.NeedsRehash(x.PasswordHash) {
			if h, err := passwords.Hash(req.Password); err == nil {
				x.PasswordHash = h
			}
		}
		return nil
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := s.startSession(w, r, u, []string{"pwd"}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	s.noteDevice(r.Context(), w, r, u)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"next": safeReturn(req.ReturnTo)})
}

func (s *Service) checkPassword(u User, password string) (bool, error) {
	if passwords.IsImported(u.PasswordHash) {
		return passwords.CheckImported(password, u.PasswordHash)
	}
	return passwords.Check(password, u.PasswordHash)
}

// startSession creates a session for u and sets the cookie.
func (s *Service) startSession(w http.ResponseWriter, r *http.Request, u User, methods []string) error {
	now := s.Now()
	sess := session.Session{
		ID:          rand.Text(),
		UserID:      u.ID,
		TenantID:    u.TenantID,
		Realm:       u.Realm,
		AuthMethods: methods,
		IssuedAt:    now,
		ExpiresAt:   now.Add(s.SessionTTL),
		LastSeen:    now,
		UserAgent:   r.UserAgent(),
		RemoteAddr:  httpx.ClientIP(r),
	}
	if err := s.Sessions.Put(r.Context(), sess); err != nil {
		return err
	}
	return s.Cookies.Write(w, sess)
}

type linkRequest struct {
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
	ReturnTo string `json:"return_to"`
}

func (s *Service) requestLink(w http.ResponseWriter, r *http.Request) {
	var req linkRequest
	if err := httpx.DecodeJSON(r, 4<<10, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	email, err := NormalizeEmail(req.Email)
	if err == nil {
		if _, err := s.Store.ByEmail(r.Context(), req.TenantID, email); err == nil {
			s.sendLink(r.Context(), email, req.TenantID, safeReturn(req.ReturnTo))
		}
	}
	// Always the same answer, whether or not the account exists.
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "check your email"})
}

func (s *Service) sendLink(ctx context.Context, email, tenantID, returnTo string) {
	link, err := s.Links.Create(ctx, email, tenantID, returnTo)
	if err != nil {
		s.Log.Error("sign-in link", "err", err)
		return
	}
	err = s.Mail.Send(ctx, notify.Message{
		From:    "Tallowbrook <no-reply@tallowbrook.example>",
		To:      []string{email},
		Subject: "Your Tallowbrook sign-in link",
		Text:    "Use this link within 15 minutes to sign in:\n\n" + link + "\n\nIf you did not ask for it, you can ignore this email.",
	})
	if err != nil {
		s.Log.Error("sign-in link email", "err", err)
	}
}

func (s *Service) redeemLink(w http.ResponseWriter, r *http.Request) {
	t, err := s.Links.Redeem(r.Context(), r.URL.Query().Get("t"))
	if err != nil {
		http.Redirect(w, r, "/signin?error=link", http.StatusSeeOther)
		return
	}
	u, err := s.Store.ByEmail(r.Context(), t.TenantID, t.Email)
	if err != nil || u.Status == StatusDisabled {
		http.Redirect(w, r, "/signin?error=link", http.StatusSeeOther)
		return
	}
	u, err = s.Store.Update(r.Context(), u.ID, func(x *User) error {
		x.EmailVerified = true
		if x.Status == StatusPendingID {
			x.Status = StatusActive
		}
		return nil
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := s.startSession(w, r, u, []string{"email"}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	http.Redirect(w, r, safeReturn(t.ReturnTo), http.StatusSeeOther)
}

func (s *Service) currentUser(r *http.Request) (User, error) {
	sid, _, err := s.Cookies.Read(r, s.Now())
	if err != nil {
		return User{}, httpx.ErrUnauthorized
	}
	sess, err := s.Sessions.Get(r.Context(), sid)
	if err != nil {
		return User{}, httpx.ErrUnauthorized
	}
	return s.Store.Get(r.Context(), sess.UserID)
}

func (s *Service) me(w http.ResponseWriter, r *http.Request) {
	u, err := s.currentUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

type profileUpdate struct {
	Name   *string `json:"name"`
	Locale *string `json:"locale"`
}

func (s *Service) updateMe(w http.ResponseWriter, r *http.Request) {
	u, err := s.currentUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var req profileUpdate
	if err := httpx.DecodeJSON(r, 4<<10, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	name, locale := u.Name, u.Locale
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if req.Locale != nil {
		locale = *req.Locale
	}
	if err := ValidateProfile(name, locale); err != nil {
		httpx.WriteError(w, r, httpx.BadRequest(err.Error()))
		return
	}
	u, err = s.Store.Update(r.Context(), u.ID, func(x *User) error {
		x.Name, x.Locale = name, locale
		return nil
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

// safeReturn keeps post-sign-in redirects on our own origin.
func safeReturn(p string) string {
	u, err := url.Parse(p)
	if err != nil || p == "" || u.IsAbs() || u.Host != "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, "\\") {
		return "/"
	}
	return p
}
