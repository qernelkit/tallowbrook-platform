// Package devicecerts issues certificates for workforce laptops (from the
// MDM agent's CSR) and intermediate CAs for depot gateways, under the issuing
// CA E2-1.
package devicecerts

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"

	"tallowbrook.example/identity/internal/keyfile"
)

const (
	deviceLifetime  = 397 * 24 * time.Hour
	gatewayLifetime = 3 * 365 * 24 * time.Hour
)

var (
	serialPattern = regexp.MustCompile(`^[A-Z0-9]{8,20}$`)
	depotPattern  = regexp.MustCompile(`^D[0-9]{3}$`)
)

// Issuer signs device and gateway certificates.
type Issuer struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	now    func() time.Time
}

// NewIssuer loads the issuing CA certificate and key.
func NewIssuer(certPath, keyPath string) (*Issuer, error) {
	chain, err := keyfile.Chain(certPath)
	if err != nil {
		return nil, err
	}
	key, err := keyfile.Signer(keyPath)
	if err != nil {
		return nil, err
	}
	return &Issuer{caCert: chain[0], caKey: key, now: time.Now}, nil
}

func (i *Issuer) parseRequest(csrDER []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("devicecerts: request is not signed by its own key")
	}
	return csr, nil
}

// IssueLaptop signs a client certificate for an enrolled laptop.
func (i *Issuer) IssueLaptop(csrDER []byte, serial, owner string) ([]byte, error) {
	if !serialPattern.MatchString(serial) {
		return nil, fmt.Errorf("devicecerts: bad serial %q", serial)
	}
	csr, err := i.parseRequest(csrDER)
	if err != nil {
		return nil, err
	}
	now := i.now()
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: serial, Organization: []string{"Tallowbrook"}, OrganizationalUnit: []string{"Workforce Devices"}},
		DNSNames:    []string{serial + ".devices.tallowbrook.example"},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(deviceLifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	tmpl.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: ownerOID, Value: owner}}
	return i.issue(tmpl, csr.PublicKey)
}

// IssueGatewayCA signs an intermediate for a depot gateway. Gateways issue
// short-lived certificates to the scanners in their depot.
func (i *Issuer) IssueGatewayCA(csrDER []byte, depotID string) ([]byte, error) {
	if !depotPattern.MatchString(depotID) {
		return nil, fmt.Errorf("devicecerts: bad depot id %q", depotID)
	}
	csr, err := i.parseRequest(csrDER)
	if err != nil {
		return nil, err
	}
	now := i.now()
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Depot " + depotID + " Gateway CA", Organization: []string{"Tallowbrook"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(gatewayLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		PermittedDNSDomains:   []string{depotID + ".depots.tallowbrook.example"},
	}
	return i.issue(tmpl, csr.PublicKey)
}

// ownerOID carries the owning employee's ID in the subject.
var ownerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59841, 1, 2}

func (i *Issuer) issue(tmpl *x509.Certificate, pub any) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.caCert, pub, i.caKey)
	if err != nil {
		return nil, fmt.Errorf("devicecerts: sign: %w", err)
	}
	return der, nil
}
