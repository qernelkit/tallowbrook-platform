// Package provisioning sets up courier handsets. A new handset generates its
// own key pair in the courier app and sends the public half with its
// provisioning request; the bundle comes back sealed to that key, so it can
// travel through the depot Wi-Fi and the MDM queue without exposing the
// handset's credentials.
package provisioning

import (
	"context"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"tallowbrook.example/identity/internal/sealing"
)

var deviceIDPattern = regexp.MustCompile(`^H-[0-9A-F]{12}$`)

// Request is sent by the courier app.
type Request struct {
	DeviceID         string `json:"device_id"`
	DepotID          string `json:"depot_id"`
	CourierID        string `json:"courier_id"`
	EncapsulationKey []byte `json:"encapsulation_key"`
}

// Response carries the sealed bundle.
type Response struct {
	Ciphertext []byte `json:"ciphertext"`
	Bundle     []byte `json:"bundle"`
}

// bundle is what the handset needs to start work.
type bundle struct {
	DeviceID        string    `json:"device_id"`
	DepotID         string    `json:"depot_id"`
	APIBase         string    `json:"api_base"`
	EnrollmentToken string    `json:"enrollment_token"`
	IssuedAt        time.Time `json:"issued_at"`
}

// Couriers checks that a courier may provision a handset at a depot.
type Couriers interface {
	CanProvision(ctx context.Context, courierID, depotID string) (bool, error)
}

// Provisioner builds bundles.
type Provisioner struct {
	Couriers Couriers
	APIBase  string
	now      func() time.Time
}

func New(couriers Couriers, apiBase string) *Provisioner {
	return &Provisioner{Couriers: couriers, APIBase: apiBase, now: time.Now}
}

// Bundle answers one provisioning request.
func (p *Provisioner) Bundle(ctx context.Context, req Request) (*Response, error) {
	if !deviceIDPattern.MatchString(req.DeviceID) {
		return nil, fmt.Errorf("provisioning: bad device id %q", req.DeviceID)
	}
	ok, err := p.Couriers.CanProvision(ctx, req.CourierID, req.DepotID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("provisioning: courier is not assigned to this depot")
	}
	ek, err := mlkem.NewEncapsulationKey768(req.EncapsulationKey)
	if err != nil {
		return nil, fmt.Errorf("provisioning: handset key: %w", err)
	}
	shared, ct := ek.Encapsulate()
	body, err := json.Marshal(bundle{
		DeviceID:        req.DeviceID,
		DepotID:         req.DepotID,
		APIBase:         p.APIBase,
		EnrollmentToken: rand.Text(),
		IssuedAt:        p.now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	sealed, err := sealing.Seal(shared, body, []byte(req.DeviceID))
	if err != nil {
		return nil, err
	}
	return &Response{Ciphertext: ct, Bundle: sealed}, nil
}
