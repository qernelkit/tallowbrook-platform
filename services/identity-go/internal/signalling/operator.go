package signalling

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

// OperatorGateway is the operator console's way into calls. The console talks
// to it over the internal network; the gateway holds the operator end of the
// call's end-to-end channel.
type OperatorGateway struct {
	Rooms *Rooms

	mu    sync.Mutex
	calls map[string]*EndToEnd
}

// Routes registers the operator endpoints.
func (o *OperatorGateway) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /operator/calls/{room}", o.invite)
	mux.HandleFunc("POST /operator/calls/{room}/accept", o.accept)
	mux.HandleFunc("POST /operator/calls/{room}/say", o.say)
}

type inviteResponse struct {
	Room  string `json:"room"`
	Share []byte `json:"share"`
}

func (o *OperatorGateway) invite(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	e, share, err := NewEndToEnd(room)
	if err != nil {
		http.Error(w, "could not start call", http.StatusInternalServerError)
		return
	}
	o.mu.Lock()
	if o.calls == nil {
		o.calls = make(map[string]*EndToEnd)
	}
	o.calls[room] = e
	o.mu.Unlock()
	o.Rooms.Open(room, r.URL.Query().Get("record") == "1")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(inviteResponse{Room: room, Share: share})
}

func (o *OperatorGateway) call(room string) (*EndToEnd, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	e, ok := o.calls[room]
	return e, ok
}

func (o *OperatorGateway) accept(w http.ResponseWriter, r *http.Request) {
	e, ok := o.call(r.PathValue("room"))
	if !ok {
		http.Error(w, "no such call", http.StatusNotFound)
		return
	}
	share, err := io.ReadAll(io.LimitReader(r.Body, 256))
	if err != nil || e.Accept(share) != nil {
		http.Error(w, "courier share rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type sayRequest struct {
	From string `json:"from"`
	Kind string `json:"kind"`
	Text string `json:"text"`
}

func (o *OperatorGateway) say(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	e, ok := o.call(room)
	if !ok {
		http.Error(w, "no such call", http.StatusNotFound)
		return
	}
	var req sayRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&req); err != nil {
		http.Error(w, "bad message", http.StatusBadRequest)
		return
	}
	body, err := e.Seal([]byte(req.Text))
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err := o.Rooms.Relay(Message{Room: room, From: req.From, Kind: req.Kind, Body: body}); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
