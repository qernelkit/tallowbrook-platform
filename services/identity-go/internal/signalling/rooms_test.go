package signalling

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestJoinLimits(t *testing.T) {
	rs := NewRooms()
	rs.Open("r1", false)
	if _, err := rs.Join("r1", "op-1", RoleOperator); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Join("r1", "c-1", RoleCourier); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Join("r1", "op-2", RoleOperator); !errors.Is(err, ErrRoomFull) {
		t.Fatalf("second operator: %v", err)
	}
	if _, err := rs.Join("nope", "op-1", RoleOperator); !errors.Is(err, ErrUnknownRoom) {
		t.Fatalf("unknown room: %v", err)
	}
}

func TestRelayReachesOthersOnly(t *testing.T) {
	rs := NewRooms()
	rs.Open("r1", false)
	op, _ := rs.Join("r1", "op-1", RoleOperator)
	c, _ := rs.Join("r1", "c-1", RoleCourier)
	if err := rs.Relay(Message{Room: "r1", From: "op-1", Kind: "offer", Body: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-c.inbox:
		if m.Kind != "offer" || m.At.IsZero() {
			t.Fatalf("got %+v", m)
		}
	default:
		t.Fatal("courier got nothing")
	}
	select {
	case m := <-op.inbox:
		t.Fatalf("sender received its own message: %+v", m)
	default:
	}
	if err := rs.Relay(Message{Room: "r1", From: "stranger"}); !errors.Is(err, ErrNotInRoom) {
		t.Fatalf("stranger: %v", err)
	}
}

func TestLeaveClosesEmptyRoom(t *testing.T) {
	rs := NewRooms()
	rs.Open("r1", true)
	rs.Join("r1", "op-1", RoleOperator)
	rs.Leave("r1", "op-1")
	if _, err := rs.Join("r1", "c-1", RoleCourier); !errors.Is(err, ErrUnknownRoom) {
		t.Fatalf("room survived: %v", err)
	}
}

func TestExpire(t *testing.T) {
	now := time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)
	rs := NewRooms()
	rs.now = func() time.Time { return now }
	rs.Open("old", false)
	now = now.Add(3 * time.Hour)
	rs.Open("new", false)
	if n := rs.Expire(2 * time.Hour); n != 1 {
		t.Fatalf("expired %d rooms", n)
	}
}

func TestRingIsStable(t *testing.T) {
	r := NewRing("sig-a", "sig-b", "sig-c")
	owners := map[string]string{}
	for i := 0; i < 200; i++ {
		room := fmt.Sprintf("room-%d", i)
		o, ok := r.Owner(room)
		if !ok {
			t.Fatal("no owner")
		}
		owners[room] = o
	}
	r.Remove("sig-c")
	moved := 0
	for room, before := range owners {
		after, _ := r.Owner(room)
		if before != "sig-c" && after != before {
			moved++
		}
	}
	if moved != 0 {
		t.Fatalf("%d rooms moved off nodes that stayed", moved)
	}
}

func TestRingSlot(t *testing.T) {
	r := NewRing("sig-a", "sig-b")
	a, _ := r.Slot("node-7")
	b, _ := r.Slot("node-7")
	if a != b {
		t.Fatal("slot not stable within a process")
	}
	if _, ok := NewRing().Slot("x"); ok {
		t.Fatal("empty ring returned a slot")
	}
}
