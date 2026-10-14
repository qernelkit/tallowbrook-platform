package signalling

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

// The recording bridge joins support calls that the courier agreed to record.
// It terminates the media transport's key agreement, then hands the derived
// keys to the recorder worker, which writes the call to the archive.

// mediaKeyingLength is two master keys and two salts for the 128-bit profiles.
const mediaKeyingLength = 2 * (16 + 14)

// Recorder receives the keys for one recorded call.
type Recorder interface {
	Begin(ctx context.Context, remote net.Addr, profile string, keying []byte) error
}

// Bridge is the recording bridge listener.
type Bridge struct {
	ln  net.Listener
	rec Recorder
	log *slog.Logger
}

// NewBridge creates a fresh certificate for bridgeHost and starts listening on addr.
func NewBridge(bridgeHost, addr string, rec Recorder, log *slog.Logger) (*Bridge, error) {
	cert, err := selfsign.GenerateSelfSignedWithDNS(bridgeHost)
	if err != nil {
		return nil, err
	}
	conf := &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		CipherSuites:           []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, dtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_128_GCM, dtls.SRTP_AES128_CM_HMAC_SHA1_80},
		EllipticCurves:         []elliptic.Curve{elliptic.X25519, elliptic.P256},
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := dtls.Listen("udp", udpAddr, conf)
	if err != nil {
		return nil, fmt.Errorf("signalling: bridge listen: %w", err)
	}
	return &Bridge{ln: ln, rec: rec, log: log}, nil
}

// Serve accepts calls until ctx is done.
func (b *Bridge) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		b.ln.Close()
	}()
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go b.handle(ctx, conn)
	}
}

func (b *Bridge) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	dc, ok := conn.(*dtls.Conn)
	if !ok {
		return
	}
	if err := dc.HandshakeContext(ctx); err != nil {
		b.log.Info("bridge: peer did not complete setup", "remote", conn.RemoteAddr().String(), "err", err)
		return
	}
	profile, ok := dc.SelectedSRTPProtectionProfile()
	if !ok {
		b.log.Warn("bridge: peer offered no media profile", "remote", conn.RemoteAddr().String())
		return
	}
	state, ok := dc.ConnectionState()
	if !ok {
		return
	}
	keying, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, mediaKeyingLength)
	if err != nil {
		b.log.Error("bridge: export keys", "err", err)
		return
	}
	if err := b.rec.Begin(ctx, conn.RemoteAddr(), fmt.Sprintf("0x%04x", uint16(profile)), keying); err != nil {
		b.log.Error("bridge: recorder refused call", "err", err)
	}
}

// ErrNoRecorder is returned when recording is requested but no worker is attached.
var ErrNoRecorder = errors.New("signalling: no recorder attached")
