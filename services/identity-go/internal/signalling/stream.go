package signalling

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Handler exposes rooms over HTTP: participants POST messages and read their
// inbox as a server-sent event stream.
type Handler struct {
	Rooms *Rooms
	Ring  *Ring
	Self  string
	Log   *slog.Logger
}

// Routes registers the signalling endpoints.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /rooms/{room}/messages", h.post)
	mux.HandleFunc("GET /rooms/{room}/events", h.events)
}

func (h *Handler) redirectIfElsewhere(w http.ResponseWriter, r *http.Request, room string) bool {
	owner, ok := h.Ring.Owner(room)
	if !ok || owner == h.Self {
		return false
	}
	w.Header().Set("Location", "https://"+owner+r.URL.RequestURI())
	w.WriteHeader(http.StatusTemporaryRedirect)
	return true
}

func (h *Handler) post(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	if h.redirectIfElsewhere(w, r, room) {
		return
	}
	var msg Message
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&msg); err != nil {
		http.Error(w, "bad message", http.StatusBadRequest)
		return
	}
	msg.Room = room
	msg.From = r.Header.Get("X-Participant")
	if err := h.Rooms.Relay(msg); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	if h.redirectIfElsewhere(w, r, room) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	pid := r.Header.Get("X-Participant")
	role := Role(r.URL.Query().Get("role"))
	if role != RoleOperator && role != RoleCourier {
		http.Error(w, "role must be operator or courier", http.StatusBadRequest)
		return
	}
	h.Rooms.Open(room, r.URL.Query().Get("record") == "1")
	p, err := h.Rooms.Join(room, pid, role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer h.Rooms.Leave(room, pid)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case msg, ok := <-p.inbox:
			if !ok {
				return
			}
			b, _ := json.Marshal(msg)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.Kind, b)
			flusher.Flush()
		}
	}
}
