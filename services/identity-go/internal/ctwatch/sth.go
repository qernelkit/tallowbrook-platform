// Package ctwatch follows the Hollowmere certificate transparency log and
// raises an alert for any certificate naming a tallowbrook.example host that
// our own CAs did not issue.
package ctwatch

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const hollowmereLogKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9xA9tWG8c/J660p+NQEmywyTXCM4
otVBMxRZWWNdYwcwHTYRQC9HBs/wP/9CL4txzT6uCBctbXLWIlYaIxJT0Q==
-----END PUBLIC KEY-----
`

const watchedSuffix = ".tallowbrook.example"

// treeHead is the get-sth response (RFC 6962 section 4.3).
type treeHead struct {
	TreeSize  uint64 `json:"tree_size"`
	Timestamp uint64 `json:"timestamp"`
	RootHash  []byte `json:"sha256_root_hash"`
	Signed    []byte `json:"tree_head_signature"`
	Signature []byte `json:"-"`
}

// Alert is raised for a certificate we did not issue.
type Alert struct {
	Index    uint64
	Names    []string
	Issuer   string
	NotAfter time.Time
}

// Watcher polls one log.
type Watcher struct {
	base     string
	client   *http.Client
	logKey   *ecdsa.PublicKey
	ourCAs   map[string]bool
	lastSize uint64
	alerts   chan<- Alert
	log      *slog.Logger
}

func newWatcher(base string, ourIssuers []string, alerts chan<- Alert, log *slog.Logger) (*Watcher, error) {
	block, _ := pem.Decode([]byte(hollowmereLogKey))
	if block == nil {
		return nil, errors.New("ctwatch: embedded log key is unreadable")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	logKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("ctwatch: embedded log key has the wrong type")
	}
	cas := make(map[string]bool, len(ourIssuers))
	for _, dn := range ourIssuers {
		cas[dn] = true
	}
	return &Watcher{base: base, client: &http.Client{Timeout: 20 * time.Second}, logKey: logKey, ourCAs: cas, alerts: alerts, log: log}, nil
}

// NewHollowmere watches the Hollowmere 2026h2 shard.
func NewHollowmere(ourIssuers []string, alerts chan<- Alert, log *slog.Logger) (*Watcher, error) {
	return newWatcher("https://ct.hollowmere.example/2026h2", ourIssuers, alerts, log)
}

func (w *Watcher) getJSON(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ctwatch: %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// splitSigned unpacks a DigitallySigned struct: hash and signature algorithm
// code points, then a length-prefixed signature.
func splitSigned(ds []byte) ([]byte, error) {
	if len(ds) < 4 {
		return nil, errors.New("ctwatch: short tree head signature")
	}
	if ds[0] != 4 || ds[1] != 3 {
		return nil, fmt.Errorf("ctwatch: unexpected signature scheme %d/%d", ds[0], ds[1])
	}
	n := int(binary.BigEndian.Uint16(ds[2:4]))
	if len(ds) != 4+n {
		return nil, errors.New("ctwatch: tree head signature length mismatch")
	}
	return ds[4:], nil
}

func (w *Watcher) verifyTreeHead(sth *treeHead) error {
	if len(sth.RootHash) != 32 {
		return errors.New("ctwatch: root hash must be 32 bytes")
	}
	treeHeadInput := make([]byte, 0, 50)
	treeHeadInput = append(treeHeadInput, 0, 1) // v1, tree_hash
	treeHeadInput = binary.BigEndian.AppendUint64(treeHeadInput, sth.Timestamp)
	treeHeadInput = binary.BigEndian.AppendUint64(treeHeadInput, sth.TreeSize)
	treeHeadInput = append(treeHeadInput, sth.RootHash...)
	digest := sha256.Sum256(treeHeadInput)
	if !ecdsa.VerifyASN1(w.logKey, digest[:], sth.Signature) {
		return errors.New("ctwatch: tree head signature does not verify")
	}
	return nil
}

type entriesResponse struct {
	Entries []struct {
		LeafInput []byte `json:"leaf_input"`
	} `json:"entries"`
}

// Poll fetches the tree head and every entry added since the last poll.
func (w *Watcher) Poll(ctx context.Context) error {
	var sth treeHead
	if err := w.getJSON(ctx, "/ct/v1/get-sth", &sth); err != nil {
		return err
	}
	sig, err := splitSigned(sth.Signed)
	if err != nil {
		return err
	}
	sth.Signature = sig
	if err := w.verifyTreeHead(&sth); err != nil {
		return err
	}
	for start := w.lastSize; start < sth.TreeSize; {
		end := min(start+255, sth.TreeSize-1)
		var page entriesResponse
		if err := w.getJSON(ctx, fmt.Sprintf("/ct/v1/get-entries?start=%d&end=%d", start, end), &page); err != nil {
			return err
		}
		if len(page.Entries) == 0 {
			break
		}
		for i, e := range page.Entries {
			w.inspect(start+uint64(i), e.LeafInput)
		}
		start += uint64(len(page.Entries))
		w.lastSize = start
	}
	return nil
}

// inspect looks at one MerkleTreeLeaf; only x509_entry leaves carry a full
// certificate (precertificates are skipped).
func (w *Watcher) inspect(index uint64, leaf []byte) {
	if len(leaf) < 15 || leaf[0] != 0 || leaf[1] != 0 {
		return
	}
	if binary.BigEndian.Uint16(leaf[10:12]) != 0 {
		return
	}
	n := int(leaf[12])<<16 | int(leaf[13])<<8 | int(leaf[14])
	if len(leaf) < 15+n {
		return
	}
	c, err := x509.ParseCertificate(leaf[15 : 15+n])
	if err != nil {
		return
	}
	var ours []string
	for _, name := range c.DNSNames {
		if strings.HasSuffix(name, watchedSuffix) {
			ours = append(ours, name)
		}
	}
	if len(ours) == 0 || w.ourCAs[c.Issuer.String()] {
		return
	}
	w.log.Warn("ctwatch: unexpected issuer for our names", "index", index, "issuer", c.Issuer.String(), "names", ours)
	w.alerts <- Alert{Index: index, Names: ours, Issuer: c.Issuer.String(), NotAfter: c.NotAfter}
}
