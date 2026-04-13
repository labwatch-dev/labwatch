// Package transport handles sending collected metrics to the API.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/labwatch-dev/labwatch/internal/config"
)

// Payload is the data sent to the API on each collection interval.
type Payload struct {
	LabID      string                 `json:"lab_id"`
	Hostname   string                 `json:"hostname"`
	Timestamp  string                 `json:"timestamp"`
	Collectors map[string]interface{} `json:"collectors"`
}

// Sender handles authenticated HTTP communication with the API.
type Sender struct {
	cfg       *config.Config
	client    *http.Client
	userAgent string
}

// New creates a new Sender. Version should be the agent version string (e.g., "0.2.1").
func New(cfg *config.Config, version ...string) (*Sender, error) {
	ua := "labwatch/unknown"
	if len(version) > 0 && version[0] != "" {
		ua = "labwatch/" + version[0]
	}
	return &Sender{
		cfg: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent: ua,
	}, nil
}

// Register registers this agent with the API and saves the token.
func (s *Sender) Register() error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	body, err := json.Marshal(map[string]string{
		"hostname": hostname,
	})
	if err != nil {
		return fmt.Errorf("marshaling registration body: %w", err)
	}

	req, err := http.NewRequest("POST", s.cfg.APIEndpoint+"/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.AdminSecret != "" {
		req.Header.Set("X-Admin-Secret", s.cfg.AdminSecret)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Token string `json:"token"`
		LabID string `json:"lab_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("parsing registration response: %w", err)
	}

	fmt.Printf("Lab ID: %s\n", result.LabID)
	fmt.Printf("Token: %s\n", result.Token)
	fmt.Println("Add these to your config file (/etc/labwatch/config.yaml)")

	return nil
}

// Send transmits a payload to the API.
func (s *Sender) Send(ctx context.Context, payload Payload) error {
	payload.LabID = s.cfg.LabID
	payload.Hostname = s.cfg.Hostname

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.cfg.APIEndpoint+"/ingest", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
