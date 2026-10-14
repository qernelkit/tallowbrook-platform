// Package partners reads partner files. Harborline Staffing sends a nightly
// roster of the agency drivers working Tallowbrook depots.
package partners

import (
	"fmt"
	"strings"
	"time"
)

// Driver is one roster entry.
type Driver struct {
	AgencyID   string
	GivenName  string
	FamilyName string
	Email      string
	DepotID    string
	StartDate  time.Time
	EndDate    time.Time // zero if open-ended
	Active     bool
}

// Fixed-width layout of a decrypted record body, as in Harborline's
// "Roster Export v3" document.
var layout = []struct {
	name       string
	start, end int
}{
	{"agency_id", 0, 10},
	{"given_name", 10, 40},
	{"family_name", 40, 70},
	{"email", 70, 130},
	{"depot", 130, 134},
	{"start", 134, 142},
	{"end", 142, 150},
	{"status", 150, 151},
}

const recordWidth = 151

func parseDriver(body []byte) (Driver, error) {
	if len(body) != recordWidth {
		return Driver{}, fmt.Errorf("partners: record is %d bytes, want %d", len(body), recordWidth)
	}
	f := make(map[string]string, len(layout))
	for _, col := range layout {
		f[col.name] = strings.TrimSpace(string(body[col.start:col.end]))
	}
	d := Driver{
		AgencyID:   f["agency_id"],
		GivenName:  f["given_name"],
		FamilyName: f["family_name"],
		Email:      strings.ToLower(f["email"]),
		DepotID:    f["depot"],
		Active:     f["status"] == "A",
	}
	var err error
	if d.StartDate, err = time.Parse("20060102", f["start"]); err != nil {
		return Driver{}, fmt.Errorf("partners: %s: start date: %w", d.AgencyID, err)
	}
	if f["end"] != "" && f["end"] != "00000000" {
		if d.EndDate, err = time.Parse("20060102", f["end"]); err != nil {
			return Driver{}, fmt.Errorf("partners: %s: end date: %w", d.AgencyID, err)
		}
	}
	if d.AgencyID == "" || !strings.Contains(d.Email, "@") {
		return Driver{}, fmt.Errorf("partners: record without agency id or email")
	}
	return d, nil
}

// Working reports whether the driver may sign in on day.
func (d Driver) Working(day time.Time) bool {
	if !d.Active || day.Before(d.StartDate) {
		return false
	}
	return d.EndDate.IsZero() || !day.After(d.EndDate)
}
