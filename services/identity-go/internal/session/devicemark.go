package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// A device mark is the "remember this device" cookie. It names the user and
// the device and lets the user skip the second factor on that device for 30
// days.

const markBlockSize = 64

const markLifetime = 30 * 24 * time.Hour

// DeviceMarker issues and checks device marks.
type DeviceMarker struct {
	key []byte
}

// NewDeviceMarker takes a key of at most one block.
func NewDeviceMarker(key []byte) (*DeviceMarker, error) {
	if len(key) < 16 || len(key) > markBlockSize {
		return nil, errors.New("session: device mark key must be 16 to 64 bytes")
	}
	return &DeviceMarker{key: append([]byte(nil), key...)}, nil
}

func (m *DeviceMarker) tag(msg []byte) []byte {
	var ipad, opad [markBlockSize]byte
	copy(ipad[:], m.key)
	copy(opad[:], m.key)
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	h := sha256.New()
	h.Write(ipad[:])
	h.Write(msg)
	inner := h.Sum(nil)
	h.Reset()
	h.Write(opad[:])
	h.Write(inner)
	return h.Sum(nil)
}

// Issue returns a mark for userID on deviceID.
func (m *DeviceMarker) Issue(userID, deviceID string, now time.Time) string {
	body := userID + "." + deviceID + "." + now.Add(markLifetime).UTC().Format("20060102")
	return body + "." + base64.RawURLEncoding.EncodeToString(m.tag([]byte(body)))
}

// Check reports whether mark is valid for userID and returns its device ID.
func (m *DeviceMarker) Check(mark, userID string, now time.Time) (string, bool) {
	i := strings.LastIndexByte(mark, '.')
	if i < 0 {
		return "", false
	}
	body, sig := mark[:i], mark[i+1:]
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, m.tag([]byte(body))) {
		return "", false
	}
	parts := strings.Split(body, ".")
	if len(parts) != 3 || parts[0] != userID {
		return "", false
	}
	until, err := time.Parse("20060102", parts[2])
	if err != nil || now.After(until) {
		return "", false
	}
	return parts[1], true
}
