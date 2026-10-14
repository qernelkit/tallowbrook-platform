package sshca

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Identity resolves a workforce access token to a username.
type Identity interface {
	Username(ctx context.Context, accessToken string) (string, error)
}

// API is the HTTP interface of the CA, used by the `tb ssh login` helper.
type API struct {
	CA       *Authority
	Identity Identity
	TTL      time.Duration
	Log      *slog.Logger
}

type certResponse struct {
	Certificate string    `json:"certificate"`
	ValidUntil  time.Time `json:"valid_until"`
}

// Routes registers the CA endpoints.
func (a *API) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/user-certs", a.issue)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}

func (a *API) issue(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	user, err := a.Identity.Username(r.Context(), tok)
	if err != nil {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(body)
	if err != nil {
		http.Error(w, "body must be one authorized_keys line", http.StatusBadRequest)
		return
	}
	cert, err := a.CA.IssueUser(pub, CertRequest{KeyID: user + "@workforce", Principals: []string{user}, TTL: a.TTL})
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errBadRequest) {
			status = http.StatusBadRequest
		}
		http.Error(w, err.Error(), status)
		return
	}
	a.Log.Info("user certificate issued", "user", user, "serial", cert.Serial)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(certResponse{
		Certificate: string(ssh.MarshalAuthorizedKey(cert)),
		ValidUntil:  time.Unix(int64(cert.ValidBefore), 0).UTC(),
	})
}

var errBadRequest = errors.New("sshca: bad request")
