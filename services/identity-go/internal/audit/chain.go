// Package audit records security events (sign-ins, certificate issuance,
// break-glass use, admin changes) in an append-only log whose entries are
// chained, so a deleted or edited entry breaks every later link.
package audit

import (
	"compress/gzip"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one audit entry.
type Event struct {
	At     time.Time         `json:"at"`
	Actor  string            `json:"actor"`
	Action string            `json:"action"`
	Target string            `json:"target,omitempty"`
	Remote string            `json:"remote,omitempty"`
	Detail map[string]string `json:"detail,omitempty"`
	Prev   string            `json:"prev"`
}

// Log is the audit log of one process.
type Log struct {
	mu         sync.Mutex
	dir        string
	f          *os.File
	head       []byte
	count      int
	perSegment int
	now        func() time.Time
}

// Open starts a new segment in dir. A process never appends to an older
// segment; the first entry of each segment links to the last head recorded in
// dir/HEAD.
func Open(dir string, perSegment int) (*Log, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	l := &Log{dir: dir, perSegment: perSegment, now: time.Now}
	if raw, err := os.ReadFile(filepath.Join(dir, "HEAD")); err == nil {
		if h, err := hex.DecodeString(string(raw)); err == nil {
			l.head = h
		}
	}
	if err := l.rotate(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) rotate() error {
	if l.f != nil {
		if err := l.f.Close(); err != nil {
			return err
		}
	}
	name := filepath.Join(l.dir, l.now().UTC().Format("20060102T150405")+".jsonl.gz")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	l.f, l.count = f, 0
	return nil
}

// link writes entry to w as its own gzip member, so the segment stays a valid
// .gz file after every append, and returns the hash that chains entry to prev.
func link(w io.Writer, prev, entry []byte) ([]byte, error) {
	zw := gzip.NewWriter(w)
	h := sha3.New256()
	h.Write(prev)
	if _, err := io.MultiWriter(zw, h).Write(entry); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Append records ev.
func (l *Log) Append(ev Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ev.At.IsZero() {
		ev.At = l.now().UTC()
	}
	ev.Prev = hex.EncodeToString(l.head)
	entry, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	entry = append(entry, '\n')
	head, err := link(l.f, l.head, entry)
	if err != nil {
		return fmt.Errorf("audit: append: %w", err)
	}
	l.head = head
	l.count++
	if err := os.WriteFile(filepath.Join(l.dir, "HEAD"), []byte(hex.EncodeToString(head)), 0o640); err != nil {
		return err
	}
	if l.count >= l.perSegment {
		return l.rotate()
	}
	return nil
}

// Close closes the current segment.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
