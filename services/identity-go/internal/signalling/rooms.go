// Package signalling runs operator-courier support calls: room membership,
// message fan-out, the end-to-end message channel and the recording bridge.
package signalling

import (
	"errors"
	"sync"
	"time"
)

// Role is a participant's role in a support call.
type Role string

const (
	RoleOperator Role = "operator"
	RoleCourier  Role = "courier"
)

// Participant is one member of a room.
type Participant struct {
	ID     string
	Role   Role
	Joined time.Time
	inbox  chan Message
}

// Message is one relayed signalling message. Body is opaque to the server:
// it is sealed end to end.
type Message struct {
	Room string    `json:"room"`
	From string    `json:"from"`
	Kind string    `json:"kind"` // offer, answer, candidate, chat, bye
	Body []byte    `json:"body"`
	At   time.Time `json:"at"`
}

var (
	ErrRoomFull    = errors.New("signalling: room already has an operator and a courier")
	ErrNotInRoom   = errors.New("signalling: participant is not in the room")
	ErrUnknownRoom = errors.New("signalling: unknown room")
)

// Room is one support call.
type Room struct {
	ID        string
	Created   time.Time
	Recording bool
	members   map[string]*Participant
}

// Rooms holds the rooms owned by this node.
type Rooms struct {
	mu    sync.Mutex
	rooms map[string]*Room
	now   func() time.Time
}

func NewRooms() *Rooms {
	return &Rooms{rooms: make(map[string]*Room), now: time.Now}
}

// Open creates a room, or returns the existing one.
func (rs *Rooms) Open(id string, recording bool) *Room {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if r, ok := rs.rooms[id]; ok {
		return r
	}
	r := &Room{ID: id, Created: rs.now(), Recording: recording, members: make(map[string]*Participant)}
	rs.rooms[id] = r
	return r
}

// Join adds a participant. A room holds one operator and one courier.
func (rs *Rooms) Join(roomID, participantID string, role Role) (*Participant, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	r, ok := rs.rooms[roomID]
	if !ok {
		return nil, ErrUnknownRoom
	}
	for _, m := range r.members {
		if m.Role == role && m.ID != participantID {
			return nil, ErrRoomFull
		}
	}
	p := &Participant{ID: participantID, Role: role, Joined: rs.now(), inbox: make(chan Message, 32)}
	r.members[participantID] = p
	return p, nil
}

// Leave removes a participant and closes the room when it is empty.
func (rs *Rooms) Leave(roomID, participantID string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	r, ok := rs.rooms[roomID]
	if !ok {
		return
	}
	if p, ok := r.members[participantID]; ok {
		close(p.inbox)
		delete(r.members, participantID)
	}
	if len(r.members) == 0 {
		delete(rs.rooms, roomID)
	}
}

// Relay delivers msg to every other member of its room. Slow readers drop
// messages rather than block the room.
func (rs *Rooms) Relay(msg Message) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	r, ok := rs.rooms[msg.Room]
	if !ok {
		return ErrUnknownRoom
	}
	if _, ok := r.members[msg.From]; !ok {
		return ErrNotInRoom
	}
	msg.At = rs.now()
	for id, m := range r.members {
		if id == msg.From {
			continue
		}
		select {
		case m.inbox <- msg:
		default:
		}
	}
	return nil
}

// Expire closes rooms older than maxAge.
func (rs *Rooms) Expire(maxAge time.Duration) int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	n := 0
	for id, r := range rs.rooms {
		if rs.now().Sub(r.Created) > maxAge {
			for _, p := range r.members {
				close(p.inbox)
			}
			delete(rs.rooms, id)
			n++
		}
	}
	return n
}
