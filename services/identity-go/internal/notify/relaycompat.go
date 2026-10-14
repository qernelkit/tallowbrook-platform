// Package notify sends account email (sign-in links, security alerts).
package notify

import (
	"bytes"
	"context"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// The depot mail relay predates the central submission service and is still
// the only route to the depot printers' mailboxes. It accepts a submission
// only with an X-Relay-Token header: the submission time run through the
// relay's stream cipher under the shared relay secret.

// Message is one outgoing email.
type Message struct {
	From    string
	To      []string
	Subject string
	Text    string
}

// RelayClient submits mail to the depot relay.
type RelayClient struct {
	addr string
	key  []byte
	now  func() time.Time
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewRelayClient(addr string, key []byte) *RelayClient {
	var d net.Dialer
	return &RelayClient{addr: addr, key: key, now: time.Now, dial: d.DialContext}
}

// Send submits msg.
func (r *RelayClient) Send(ctx context.Context, msg Message) error {
	if len(msg.To) == 0 {
		return fmt.Errorf("notify: no recipients")
	}
	var body bytes.Buffer
	qp := quotedprintable.NewWriter(&body)
	c, err := rc4.NewCipher(r.key)
	if err != nil {
		return err
	}
	if _, err := qp.Write([]byte(msg.Text)); err != nil {
		return err
	}
	if err := qp.Close(); err != nil {
		return err
	}
	stamp := []byte(r.now().UTC().Format(time.RFC3339))
	c.XORKeyStream(stamp, stamp)

	var out bytes.Buffer
	fmt.Fprintf(&out, "From: %s\r\n", msg.From)
	fmt.Fprintf(&out, "To: %s\r\n", strings.Join(msg.To, ", "))
	fmt.Fprintf(&out, "Subject: %s\r\n", msg.Subject)
	fmt.Fprintf(&out, "X-Relay-Token: %s\r\n", hex.EncodeToString(stamp))
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	out.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	out.Write(body.Bytes())

	conn, err := r.dial(ctx, "tcp", r.addr)
	if err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(r.addr)
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if err := cl.Mail(msg.From); err != nil {
		return err
	}
	for _, to := range msg.To {
		if err := cl.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(out.Bytes()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}
