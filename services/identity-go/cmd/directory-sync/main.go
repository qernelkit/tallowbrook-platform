// The Harborline roster appliance stalls when a ClientHello no longer fits in
// one packet, so this binary keeps the larger key shares out of its offers.

//go:debug tlsmlkem=0

// Command directory-sync pulls the nightly Harborline roster of agency
// drivers and updates their workforce accounts through the IdP's internal
// endpoint.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"tallowbrook.example/identity/internal/partners"
)

const defaultRosterURL = "https://roster.harborline.example/exports/tallowbrook/latest.hlr"

type driverUpdate struct {
	AgencyID string `json:"agency_id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Active   bool   `json:"active"`
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(context.Background(), log); err != nil {
		log.Error("directory-sync failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger) error {
	key, err := hex.DecodeString(os.Getenv("DIRSYNC_ROSTER_KEY"))
	if err != nil {
		return fmt.Errorf("DIRSYNC_ROSTER_KEY must be hex: %w", err)
	}
	reader, err := partners.NewRosterReader(key)
	if err != nil {
		return err
	}
	url := os.Getenv("DIRSYNC_ROSTER_URL")
	if url == "" {
		url = defaultRosterURL
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("DIRSYNC_HARBORLINE_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("roster download: %s", resp.Status)
	}
	drivers, err := reader.Read(resp.Body)
	if err != nil {
		return err
	}
	today := time.Now()
	updates := make([]driverUpdate, 0, len(drivers))
	for _, d := range drivers {
		updates = append(updates, driverUpdate{
			AgencyID: d.AgencyID,
			Name:     strings.TrimSpace(d.GivenName + " " + d.FamilyName),
			Email:    d.Email,
			Active:   d.Working(today),
		})
	}
	body, err := json.Marshal(updates)
	if err != nil {
		return err
	}
	idp := os.Getenv("DIRSYNC_IDP_INTERNAL")
	if idp == "" {
		idp = "http://10.40.0.10:9090"
	}
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, idp+"/internal/workforce/agency-drivers", bytes.NewReader(body))
	if err != nil {
		return err
	}
	post.Header.Set("Content-Type", "application/json")
	presp, err := http.DefaultClient.Do(post)
	if err != nil {
		return err
	}
	defer presp.Body.Close()
	if presp.StatusCode != http.StatusOK {
		return fmt.Errorf("idp sync: %s", presp.Status)
	}
	log.Info("roster synced", "drivers", len(drivers))
	return nil
}
