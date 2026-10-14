package signalling

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	"tallowbrook.example/identity/internal/keyderiv"
)

// Support calls carry their signalling (SDP offers, ICE candidates, chat)
// through the public relay. The operator's end of the session runs here, the
// courier's end runs in the courier app, and the relay only ever sees sealed
// messages.

var e2eCurve = ecdh.X25519()

var errNotReady = errors.New("signalling: session keys not agreed yet")

// EndToEnd is the operator side of one call's message channel.
type EndToEnd struct {
	local  *ecdh.PrivateKey
	aead   cipher.AEAD
	callID string
}

// NewEndToEnd creates the operator's key share. Send the returned public bytes
// to the courier app in the call invitation.
func NewEndToEnd(callID string) (*EndToEnd, []byte, error) {
	local, err := e2eCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &EndToEnd{local: local, callID: callID}, local.PublicKey().Bytes(), nil
}

// Accept completes the agreement with the courier app's share.
func (e *EndToEnd) Accept(peerShare []byte) error {
	peer, err := e2eCurve.NewPublicKey(peerShare)
	if err != nil {
		return err
	}
	shared, err := e.local.ECDH(peer)
	if err != nil {
		return err
	}
	key, err := keyderiv.Derive(shared, []byte(e.callID), "signalling e2e v1", 32)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	e.aead = aead
	return nil
}

// Seal protects one outgoing message.
func (e *EndToEnd) Seal(msg []byte) ([]byte, error) {
	if e.aead == nil {
		return nil, errNotReady
	}
	nonce := make([]byte, e.aead.NonceSize(), e.aead.NonceSize()+len(msg)+e.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return e.aead.Seal(nonce, nonce, msg, []byte(e.callID)), nil
}

// Open reads one incoming message.
func (e *EndToEnd) Open(sealed []byte) ([]byte, error) {
	if e.aead == nil {
		return nil, errNotReady
	}
	n := e.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("signalling: message too short")
	}
	return e.aead.Open(nil, sealed[:n], sealed[n:], []byte(e.callID))
}
