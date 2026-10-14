// Package breachcheck lets the sign-up page check a new password against the
// breached-password corpus without the server learning the password. The
// browser blinds a hash of the password, we evaluate it with our key, and the
// browser compares the unblinded result with the published list.
package breachcheck

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/cloudflare/circl/oprf"
)

var breachCheckSuite = oprf.SuiteP256

const maxElements = 4

// Endpoint evaluates blinded elements.
type Endpoint struct {
	srv oprf.Server
}

// NewEndpoint creates a fresh evaluation key. The published list is rebuilt
// with the same key by the nightly job that shares this process.
func NewEndpoint() (*Endpoint, []byte, error) {
	key, err := oprf.GenerateKey(breachCheckSuite, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	srv := oprf.NewServer(breachCheckSuite, key)
	pub, err := key.Public().MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return &Endpoint{srv: srv}, pub, nil
}

type request struct {
	Elements []string `json:"elements"`
}

type response struct {
	Evaluated []string `json:"evaluated"`
}

func (e *Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || len(req.Elements) == 0 || len(req.Elements) > maxElements {
		http.Error(w, "send 1 to 4 elements", http.StatusBadRequest)
		return
	}
	var evalReq oprf.EvaluationRequest
	for _, s := range req.Elements {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			http.Error(w, "elements must be base64url", http.StatusBadRequest)
			return
		}
		el := breachCheckSuite.Group().NewElement()
		if err := el.UnmarshalBinary(raw); err != nil {
			http.Error(w, "element is not on the curve", http.StatusBadRequest)
			return
		}
		evalReq.Elements = append(evalReq.Elements, el)
	}
	ev, err := e.srv.Evaluate(&evalReq)
	if err != nil {
		http.Error(w, "evaluation failed", http.StatusInternalServerError)
		return
	}
	var resp response
	for _, el := range ev.Elements {
		b, err := el.MarshalBinaryCompress()
		if err != nil {
			http.Error(w, "evaluation failed", http.StatusInternalServerError)
			return
		}
		resp.Evaluated = append(resp.Evaluated, base64.RawURLEncoding.EncodeToString(b))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
