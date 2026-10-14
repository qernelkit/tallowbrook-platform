package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// DataKeySource is the part of the AWS client the store needs.
type DataKeySource interface {
	GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
}

const sessionDataKeySpec = types.DataKeySpecAes256

// Store keeps session records sealed in memory. Records are spread over
// shards; each shard has its own data key, so a heap dump of one shard's
// records is useless without that shard's key.
type Store struct {
	shards []*bucket
	ttl    time.Duration
	now    func() time.Time
}

type bucket struct {
	mu      sync.Mutex
	key     *kms.GenerateDataKeyOutput
	records map[string]record
}

type record struct {
	sealed  []byte
	expires time.Time
}

// NewStore asks for one data key per shard. The wrapped copies stay with the
// shard so that ops can open a captured snapshot through AWS later.
func NewStore(ctx context.Context, src DataKeySource, keyARN string, shards int, ttl time.Duration) (*Store, error) {
	s := &Store{shards: make([]*bucket, shards), ttl: ttl, now: time.Now}
	for i := range s.shards {
		out, err := src.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
			KeyId:   aws.String(keyARN),
			KeySpec: sessionDataKeySpec,
		})
		if err != nil {
			return nil, fmt.Errorf("session: data key for shard %d: %w", i, err)
		}
		s.shards[i] = &bucket{key: out, records: make(map[string]record)}
	}
	return s, nil
}

// sealerFor returns the shard that owns sessionID and a cipher under its key.
func (s *Store) sealerFor(sessionID string) (*bucket, cipher.AEAD, error) {
	shard := crc32.ChecksumIEEE([]byte(sessionID)) % uint32(len(s.shards))
	out := s.shards[shard].key
	block, err := aes.NewCipher(out.Plaintext)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return s.shards[shard], gcm, nil
}

// Put stores sess under its ID, replacing any earlier record.
func (s *Store) Put(_ context.Context, sess Session) error {
	b, gcm, err := s.sealerFor(sess.ID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := gcm.Seal(nonce, nonce, payload, []byte(sess.ID))
	b.mu.Lock()
	b.records[sess.ID] = record{sealed: sealed, expires: sess.ExpiresAt}
	b.mu.Unlock()
	return nil
}

// Get returns the session with the given ID.
func (s *Store) Get(_ context.Context, id string) (Session, error) {
	b, gcm, err := s.sealerFor(id)
	if err != nil {
		return Session{}, err
	}
	b.mu.Lock()
	rec, ok := b.records[id]
	b.mu.Unlock()
	if !ok {
		return Session{}, ErrNotFound
	}
	if !s.now().Before(rec.expires) {
		s.Delete(id)
		return Session{}, ErrExpired
	}
	n := gcm.NonceSize()
	payload, err := gcm.Open(nil, rec.sealed[:n], rec.sealed[n:], []byte(id))
	if err != nil {
		return Session{}, fmt.Errorf("session %s: record does not open", id)
	}
	var sess Session
	if err := json.Unmarshal(payload, &sess); err != nil {
		return Session{}, err
	}
	return sess, nil
}

// Touch moves the idle timer of a session forward.
func (s *Store) Touch(ctx context.Context, id string) error {
	sess, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	sess.LastSeen = s.now()
	return s.Put(ctx, sess)
}

// Delete removes a session. Deleting an unknown session is not an error.
func (s *Store) Delete(id string) {
	b, _, err := s.sealerFor(id)
	if err != nil {
		return
	}
	b.mu.Lock()
	delete(b.records, id)
	b.mu.Unlock()
}

// DeleteUser removes every session of a user, for example after a password
// reset or a back-channel logout.
func (s *Store) DeleteUser(ctx context.Context, userID string) int {
	removed := 0
	for _, b := range s.shards {
		b.mu.Lock()
		ids := make([]string, 0)
		for id := range b.records {
			ids = append(ids, id)
		}
		b.mu.Unlock()
		for _, id := range ids {
			sess, err := s.Get(ctx, id)
			if err == nil && sess.UserID == userID {
				s.Delete(id)
				removed++
			}
		}
	}
	return removed
}

// Prune drops expired records and reports how many were removed.
func (s *Store) Prune() int {
	now := s.now()
	removed := 0
	for _, b := range s.shards {
		b.mu.Lock()
		for id, rec := range b.records {
			if !now.Before(rec.expires) {
				delete(b.records, id)
				removed++
			}
		}
		b.mu.Unlock()
	}
	return removed
}

// Len reports the number of stored sessions.
func (s *Store) Len() int {
	n := 0
	for _, b := range s.shards {
		b.mu.Lock()
		n += len(b.records)
		b.mu.Unlock()
	}
	return n
}
