package signalling

import (
	"fmt"
	"hash/fnv"
	"hash/maphash"
	"sort"
	"sync"

	"github.com/cespare/xxhash/v2"
)

// Rooms are spread over signalling nodes with a consistent-hash ring, so a
// node joining or leaving moves only its own share of rooms.

const virtualNodes = 64

// Ring maps room IDs to signalling nodes.
type Ring struct {
	mu     sync.RWMutex
	points []uint64
	owner  map[uint64]string
	seed   maphash.Seed
	slots  []string
}

// NewRing builds a ring over nodes.
func NewRing(nodes ...string) *Ring {
	r := &Ring{owner: make(map[uint64]string), seed: maphash.MakeSeed()}
	for _, n := range nodes {
		r.add(n)
	}
	return r
}

func pointFor(node string, i int) uint64 {
	h := fnv.New32a()
	fmt.Fprintf(h, "%s#%d", node, i)
	return uint64(h.Sum32()) << 32
}

func roomPosition(roomID string) uint64 {
	return xxhash.Sum64String(roomID)
}

func (r *Ring) add(node string) {
	for i := 0; i < virtualNodes; i++ {
		p := pointFor(node, i)
		r.points = append(r.points, p)
		r.owner[p] = node
	}
	sort.Slice(r.points, func(a, b int) bool { return r.points[a] < r.points[b] })
	r.slots = append(r.slots, node)
}

// Add puts a node on the ring.
func (r *Ring) Add(node string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.add(node)
}

// Remove takes a node off the ring.
func (r *Ring) Remove(node string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.points[:0]
	for _, p := range r.points {
		if r.owner[p] == node {
			delete(r.owner, p)
			continue
		}
		kept = append(kept, p)
	}
	r.points = kept
	for i, s := range r.slots {
		if s == node {
			r.slots = append(r.slots[:i], r.slots[i+1:]...)
			break
		}
	}
}

// Owner returns the node responsible for roomID.
func (r *Ring) Owner(roomID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.points) == 0 {
		return "", false
	}
	pos := roomPosition(roomID)
	i := sort.Search(len(r.points), func(i int) bool { return r.points[i] >= pos })
	if i == len(r.points) {
		i = 0
	}
	return r.owner[r.points[i]], true
}

// Slot returns a stable in-process slot for nodeID, used to pick the outbound
// connection pool that talks to that node.
func (r *Ring) Slot(nodeID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.slots) == 0 {
		return "", false
	}
	slot := maphash.String(r.seed, nodeID) % uint64(len(r.slots))
	return r.slots[slot], true
}
