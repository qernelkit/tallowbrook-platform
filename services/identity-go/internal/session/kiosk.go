package session

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Depot kiosks are shared terminals in the parcel depots. They hold a kiosk
// cookie naming the depot and terminal, scrambled with the depot's kiosk key
// so a curious courier cannot edit it into another depot's cookie.

// KioskTicket is the content of a kiosk cookie.
type KioskTicket struct {
	DepotID  string
	Terminal int
	Issued   time.Time
}

var errKioskCookie = errors.New("session: kiosk cookie not recognised")

// scramble applies the rolling depot key. The same call reverses it.
func scramble(b, key []byte) []byte {
	out := make([]byte, len(b))
	shift := 0
	for i := range b {
		k := key[(i+shift)%len(key)]
		out[i] = b[i] ^ k
		shift = (shift + int(k)) % len(key)
	}
	return out
}

// EncodeKiosk returns the cookie value for t.
func EncodeKiosk(t KioskTicket, depotKey []byte) (string, error) {
	if len(depotKey) == 0 {
		return "", errors.New("session: depot key not configured")
	}
	plain := fmt.Sprintf("%s|%d|%d", t.DepotID, t.Terminal, t.Issued.Unix())
	return base64.RawURLEncoding.EncodeToString(scramble([]byte(plain), depotKey)), nil
}

// DecodeKiosk parses a kiosk cookie value.
func DecodeKiosk(v string, depotKey []byte, maxAge time.Duration, now time.Time) (KioskTicket, error) {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(depotKey) == 0 {
		return KioskTicket{}, errKioskCookie
	}
	parts := strings.Split(string(scramble(raw, depotKey)), "|")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "D") {
		return KioskTicket{}, errKioskCookie
	}
	term, err := strconv.Atoi(parts[1])
	if err != nil {
		return KioskTicket{}, errKioskCookie
	}
	secs, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return KioskTicket{}, errKioskCookie
	}
	t := KioskTicket{DepotID: parts[0], Terminal: term, Issued: time.Unix(secs, 0)}
	if now.Sub(t.Issued) > maxAge {
		return KioskTicket{}, ErrExpired
	}
	return t, nil
}
