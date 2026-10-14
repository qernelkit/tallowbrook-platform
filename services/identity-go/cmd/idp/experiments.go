package main

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"

	"tallowbrook.example/identity/experiments/breachcheck"
	"tallowbrook.example/identity/experiments/logintokens"
	"tallowbrook.example/identity/internal/config"
)

// enableExperiments mounts the experiments switched on in IDP_EXPERIMENTS.
// The other experiments run in the jobs that use them, not in this binary.
func enableExperiments(cfg *config.Config, mux *http.ServeMux, log *slog.Logger) {
	if cfg.Enabled("breach-check") {
		ep, pub, err := breachcheck.NewEndpoint()
		if err != nil {
			log.Error("breach-check disabled", "err", err)
		} else {
			mux.Handle("POST /signup/password-check", ep)
			mux.HandleFunc("GET /signup/password-check/key", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, base64.RawURLEncoding.EncodeToString(pub))
			})
			log.Info("experiment enabled", "name", "breach-check")
		}
	}
	if cfg.Enabled("anon-login") {
		iss, err := logintokens.NewIssuer(cfg.AnonLoginKey)
		if err != nil {
			log.Error("anon-login disabled", "err", err)
			return
		}
		mux.HandleFunc("POST /handsets/login-tokens", func(w http.ResponseWriter, r *http.Request) {
			msg, err := io.ReadAll(io.LimitReader(r.Body, 1024))
			if err != nil {
				http.Error(w, "unreadable body", http.StatusBadRequest)
				return
			}
			sig, err := iss.Sign(msg)
			if err != nil {
				http.Error(w, "could not sign", http.StatusBadRequest)
				return
			}
			_, _ = w.Write(sig)
		})
		log.Info("experiment enabled", "name", "anon-login")
	}
}
