// Command signal runs operator-courier support call signalling and the
// recording bridge.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tallowbrook.example/identity/internal/config"
	"tallowbrook.example/identity/internal/httpx"
	"tallowbrook.example/identity/internal/signalling"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("signal stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	self, _ := os.Hostname()
	peers := strings.Split(os.Getenv("SIGNAL_NODES"), ",")
	ring := signalling.NewRing(append(peers, self)...)
	rooms := signalling.NewRooms()

	public := http.NewServeMux()
	(&signalling.Handler{Rooms: rooms, Ring: ring, Self: self, Log: log}).Routes(public)
	public.HandleFunc("GET /healthz", httpx.Health)

	operator := http.NewServeMux()
	(&signalling.OperatorGateway{Rooms: rooms}).Routes(operator)

	bridge, err := signalling.NewBridge(cfg.BridgeHost, cfg.BridgeAddr, &recorderSocket{path: "/run/recorder/calls.sock"}, log)
	if err != nil {
		return err
	}

	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n := rooms.Expire(2 * time.Hour); n > 0 {
					log.Info("rooms expired", "count", n)
				}
			}
		}
	}()

	errc := make(chan error, 3)
	go func() { errc <- bridge.Serve(ctx) }()
	go func() {
		errc <- httpx.Serve(ctx, httpx.NewServer(cfg.ListenAddr, httpx.Stack(log, public)), false, log)
	}()
	go func() {
		errc <- httpx.Serve(ctx, httpx.NewServer(cfg.InternalAddr, httpx.Stack(log, operator)), false, log)
	}()
	for i := 0; i < 3; i++ {
		if err := <-errc; err != nil {
			stop()
			return err
		}
	}
	return nil
}

// recorderSocket hands calls to the recorder worker over a local socket.
type recorderSocket struct {
	path string
}

func (s *recorderSocket) Begin(ctx context.Context, remote net.Addr, profile string, keying []byte) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", s.path)
	if err != nil {
		return err
	}
	defer conn.Close()
	return json.NewEncoder(conn).Encode(map[string]any{
		"remote":  remote.String(),
		"profile": profile,
		"keying":  keying,
	})
}
