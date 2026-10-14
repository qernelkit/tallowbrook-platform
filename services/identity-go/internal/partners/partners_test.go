package partners

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func record(agency, given, family, email, depot, start, end, status string) []byte {
	return []byte(fmt.Sprintf("%-10s%-30s%-30s%-60s%-4s%-8s%-8s%-1s", agency, given, family, email, depot, start, end, status))
}

func TestParseDriver(t *testing.T) {
	d, err := parseDriver(record("HL00012345", "Mira", "Okafor", "Mira.Okafor@harborline.example", "D014", "20260301", "00000000", "A"))
	if err != nil {
		t.Fatal(err)
	}
	if d.AgencyID != "HL00012345" || d.Email != "mira.okafor@harborline.example" || d.DepotID != "D014" || !d.Active {
		t.Fatalf("got %+v", d)
	}
	if !d.EndDate.IsZero() {
		t.Fatalf("open-ended contract got end date %s", d.EndDate)
	}
}

func TestParseDriverErrors(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{"short", []byte("HL0001")},
		{"bad start", record("HL1", "A", "B", "a@b.example", "D001", "2026-3-1", "", "A")},
		{"bad end", record("HL1", "A", "B", "a@b.example", "D001", "20260301", "soon", "A")},
		{"no email", record("HL1", "A", "B", "", "D001", "20260301", "", "A")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseDriver(tt.body); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestWorking(t *testing.T) {
	day := func(s string) time.Time { d, _ := time.Parse("2006-01-02", s); return d }
	d := Driver{Active: true, StartDate: day("2026-03-01"), EndDate: day("2026-03-31")}
	tests := map[string]bool{
		"2026-02-28": false,
		"2026-03-01": true,
		"2026-03-31": true,
		"2026-04-01": false,
	}
	for s, want := range tests {
		if got := d.Working(day(s)); got != want {
			t.Errorf("Working(%s) = %v", s, got)
		}
	}
	d.Active = false
	if d.Working(day("2026-03-10")) {
		t.Error("inactive driver working")
	}
}

func TestReadRejectsOtherFiles(t *testing.T) {
	r, err := NewRosterReader(make([]byte, 24))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(bytes.NewReader([]byte("PK\x03\x04"))); err == nil {
		t.Fatal("zip file accepted")
	}
	if _, err := NewRosterReader(make([]byte, 16)); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestReadEmptyRoster(t *testing.T) {
	r, _ := NewRosterReader(make([]byte, 24))
	drivers, err := r.Read(bytes.NewReader(magic))
	if err != nil || len(drivers) != 0 {
		t.Fatalf("got %d drivers, %v", len(drivers), err)
	}
}
