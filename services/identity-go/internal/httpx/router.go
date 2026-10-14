package httpx

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Stack wraps h with the middleware every public listener uses.
func Stack(log *slog.Logger, h http.Handler) http.Handler {
	return WithRequestID(log, Recover(AccessLog(h)))
}

// SecurityHeaders sets the headers every HTML and JSON response carries.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// Health answers liveness probes.
func Health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

// Serve runs srv until ctx is cancelled, then shuts it down gracefully.
// If withCerts is set it serves with the certificates in srv.
func Serve(ctx context.Context, srv *http.Server, withCerts bool, log *slog.Logger) error {
	errc := make(chan error, 1)
	go func() {
		var err error
		if withCerts {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
		close(errc)
	}()
	log.Info("listening", "addr", srv.Addr)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// NewServer returns a plain HTTP server with sane timeouts. The edge
// terminates the public connection in front of it.
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}
