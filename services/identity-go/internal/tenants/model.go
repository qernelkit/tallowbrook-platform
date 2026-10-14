// Package tenants stores the business customers who use Tallowbrook
// sign-in for their own staff and customers.
package tenants

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Plan is a tenant's commercial plan.
type Plan string

const (
	PlanStarter    Plan = "starter"
	PlanBusiness   Plan = "business"
	PlanEnterprise Plan = "enterprise"
)

// Tenant is one business customer.
type Tenant struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Plan        Plan      `json:"plan"`
	Domains     []string  `json:"domains"`
	SCIMURL     string    `json:"scim_url,omitempty"`
	MaxUsers    int       `json:"max_users"`
	Suspended   bool      `json:"suspended"`
	Created     time.Time `json:"created"`
	ContactMail string    `json:"contact_email"`
}

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$`)

var (
	ErrSlug   = errors.New("tenants: slug must be 3-40 lowercase letters, digits or dashes")
	ErrDomain = errors.New("tenants: domain is not valid")
	ErrPlan   = errors.New("tenants: unknown plan")
)

// UserLimit returns the user cap for plan.
func UserLimit(p Plan) (int, error) {
	switch p {
	case PlanStarter:
		return 50, nil
	case PlanBusiness:
		return 1000, nil
	case PlanEnterprise:
		return 100000, nil
	}
	return 0, ErrPlan
}

// Validate checks a tenant before it is stored.
func (t *Tenant) Validate() error {
	if !slugPattern.MatchString(t.Slug) {
		return ErrSlug
	}
	if _, err := UserLimit(t.Plan); err != nil {
		return err
	}
	for _, d := range t.Domains {
		if !validDomain(d) {
			return ErrDomain
		}
	}
	return nil
}

func validDomain(d string) bool {
	if len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// OwnsEmail reports whether an email address is in one of the tenant's
// verified domains.
func (t *Tenant) OwnsEmail(email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range t.Domains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}
