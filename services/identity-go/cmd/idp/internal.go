package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"tallowbrook.example/identity/internal/audit"
	"tallowbrook.example/identity/internal/avatars"
	"tallowbrook.example/identity/internal/courier"
	"tallowbrook.example/identity/internal/devicecerts"
	"tallowbrook.example/identity/internal/httpx"
	"tallowbrook.example/identity/internal/provisioning"
	"tallowbrook.example/identity/internal/recovery"
	"tallowbrook.example/identity/internal/scim"
	"tallowbrook.example/identity/internal/session"
	"tallowbrook.example/identity/internal/tenants"
	"tallowbrook.example/identity/internal/tokenize"
	"tallowbrook.example/identity/internal/users"
)

// internalHandlers serve the private listener that device management, the
// courier platform, the support console and directory-sync call.
type internalHandlers struct {
	log         *slog.Logger
	users       *users.Store
	tenants     *tenants.Store
	audit       *audit.Log
	devices     *devicecerts.Issuer
	provisioner *provisioning.Provisioner
	escrow      *recovery.Escrow
	webhooks    *scim.Webhooks
	tokens      *tokenize.Tokenizer
	kioskKey    []byte
}

func (h *internalHandlers) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/laptops/{serial}/certificate", h.laptopCertificate)
	mux.HandleFunc("POST /internal/gateways/{depot}/ca", h.gatewayCA)
	mux.HandleFunc("POST /internal/handsets/provision", h.provision)
	mux.HandleFunc("POST /internal/handoffs", h.handoff)
	mux.HandleFunc("POST /internal/recovery/{user}", h.enrolRecovery)
	mux.HandleFunc("POST /internal/accounts/tokenize", h.tokenize)
	mux.HandleFunc("POST /internal/workforce/agency-drivers", h.agencyDrivers)
	mux.HandleFunc("GET /internal/kiosk", h.kiosk)
	mux.HandleFunc("GET /healthz", httpx.Health)
}

func (h *internalHandlers) laptopCertificate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		httpx.WriteError(w, r, httpx.BadRequest("unreadable body"))
		return
	}
	der, err := h.devices.IssueLaptop(body, r.PathValue("serial"), r.URL.Query().Get("owner"))
	if err != nil {
		httpx.WriteError(w, r, httpx.BadRequest(err.Error()))
		return
	}
	_ = h.audit.Append(audit.Event{Actor: "mdm", Action: "laptop-certificate", Target: r.PathValue("serial")})
	w.Header().Set("Content-Type", "application/pkix-cert")
	_, _ = w.Write(der)
}

func (h *internalHandlers) gatewayCA(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		httpx.WriteError(w, r, httpx.BadRequest("unreadable body"))
		return
	}
	der, err := h.devices.IssueGatewayCA(body, r.PathValue("depot"))
	if err != nil {
		httpx.WriteError(w, r, httpx.BadRequest(err.Error()))
		return
	}
	_ = h.audit.Append(audit.Event{Actor: "depot-ops", Action: "gateway-ca", Target: r.PathValue("depot")})
	w.Header().Set("Content-Type", "application/pkix-cert")
	_, _ = w.Write(der)
}

func (h *internalHandlers) provision(w http.ResponseWriter, r *http.Request) {
	var req provisioning.Request
	if err := httpx.DecodeJSON(r, 8<<10, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	resp, err := h.provisioner.Bundle(r.Context(), req)
	if err != nil {
		httpx.WriteError(w, r, httpx.BadRequest(err.Error()))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

type handoffRequest struct {
	ParcelID   string `json:"parcel_id"`
	CourierApp string `json:"courier_app"` // hex, 32 bytes
}

func (h *internalHandlers) handoff(w http.ResponseWriter, r *http.Request) {
	var req handoffRequest
	if err := httpx.DecodeJSON(r, 2<<10, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	raw, err := hex.DecodeString(req.CourierApp)
	if err != nil || len(raw) != 32 {
		httpx.WriteError(w, r, httpx.BadRequest("courier_app must be 64 hex characters"))
		return
	}
	var appKey [32]byte
	copy(appKey[:], raw)
	ho, err := courier.New(req.ParcelID, appKey)
	if err != nil {
		httpx.WriteError(w, r, httpx.BadRequest(err.Error()))
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"parcel_id": ho.ParcelID, "code": ho.Code, "sealed": ho.Sealed})
}

func (h *internalHandlers) enrolRecovery(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("user")
	if _, err := h.users.Get(r.Context(), userID); err != nil {
		httpx.WriteError(w, r, httpx.ErrNotFound)
		return
	}
	secret := recovery.NewSecret()
	rec, err := h.escrow.Enroll(r.Context(), userID, secret)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	_ = h.audit.Append(audit.Event{Actor: "support", Action: "recovery-enrol", Target: userID})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"record": rec, "recovery_code": hex.EncodeToString(secret)})
}

func (h *internalHandlers) tokenize(w http.ResponseWriter, r *http.Request) {
	if h.tokens == nil {
		httpx.WriteError(w, r, httpx.ErrNotFound)
		return
	}
	var req struct {
		Number string `json:"number"`
	}
	if err := httpx.DecodeJSON(r, 1<<10, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tok, err := h.tokens.Tokenize(strings.ReplaceAll(req.Number, " ", ""))
	if err != nil {
		httpx.WriteError(w, r, httpx.BadRequest(err.Error()))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, tokenize.Account{Token: tok, Last4: req.Number[len(req.Number)-4:]})
}

type agencyDriver struct {
	AgencyID string `json:"agency_id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Active   bool   `json:"active"`
}

func (h *internalHandlers) agencyDrivers(w http.ResponseWriter, r *http.Request) {
	var drivers []agencyDriver
	if err := httpx.DecodeJSON(r, 4<<20, &drivers); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	created, updated := 0, 0
	for _, d := range drivers {
		email, err := users.NormalizeEmail(d.Email)
		if err != nil {
			continue
		}
		status := users.StatusActive
		if !d.Active {
			status = users.StatusDisabled
		}
		u, err := h.users.ByEmail(r.Context(), users.WorkforceTenant, email)
		if err != nil {
			nu := &users.User{TenantID: users.WorkforceTenant, Realm: session.RealmWorkforce, Email: email, Name: d.Name, Locale: "en", Status: status, EmployeeID: "HL-" + d.AgencyID}
			if h.users.Create(r.Context(), nu) == nil {
				created++
			}
			continue
		}
		if _, err := h.users.Update(r.Context(), u.ID, func(x *users.User) error { x.Name, x.Status = d.Name, status; return nil }); err == nil {
			updated++
		}
	}
	h.log.Info("agency drivers synced", "created", created, "updated", updated)
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"created": created, "updated": updated})
}

func (h *internalHandlers) kiosk(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie("tb_kiosk")
	if err != nil {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}
	t, err := session.DecodeKiosk(ck.Value, h.kioskKey, 24*time.Hour, time.Now())
	if err != nil {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"depot": t.DepotID, "terminal": t.Terminal})
}

// courierRoster answers provisioning checks from the courier platform.
type courierRoster struct{}

func (courierRoster) CanProvision(ctx context.Context, courierID, depotID string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://couriers.internal.tallowbrook.example/v1/couriers/"+courierID+"/depots/"+depotID, nil)
	if err != nil {
		return false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var body struct {
		Assigned bool `json:"assigned"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, err
	}
	return body.Assigned, nil
}

func avatarRedirect(av *avatars.URLs, cookies *session.CookieCodec, sessions *session.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sid, _, err := cookies.Read(r, time.Now())
		if err != nil {
			httpx.WriteError(w, r, httpx.ErrUnauthorized)
			return
		}
		sess, err := sessions.Get(r.Context(), sid)
		if err != nil {
			httpx.WriteError(w, r, httpx.ErrUnauthorized)
			return
		}
		u, err := av.For(sess.UserID, 128)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		http.Redirect(w, r, u, http.StatusFound)
	})
}

func decodeHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
