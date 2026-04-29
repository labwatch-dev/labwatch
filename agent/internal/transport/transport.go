// Package transport handles sending collected metrics to the API.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
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

// RegisterResult holds the credentials returned by the API after registration.
type RegisterResult struct {
	Token string `json:"token"`
	LabID string `json:"lab_id"`
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

// Register registers this agent with the API and returns the credentials.
func (s *Sender) Register() (*RegisterResult, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	body, err := json.Marshal(map[string]string{
		"hostname": hostname,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling registration body: %w", err)
	}

	req, err := http.NewRequest("POST", s.cfg.APIEndpoint+"/register", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.AdminSecret != "" {
		req.Header.Set("X-Admin-Secret", s.cfg.AdminSecret)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result RegisterResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parsing registration response: %w", err)
	}

	return &result, nil
}

// Send transmits a payload to the API with retry and exponential backoff.
// Retries up to 3 times on transient errors (network failures, 5xx responses).
// Non-retryable errors (4xx) fail immediately.
func (s *Sender) Send(ctx context.Context, payload Payload) error {
	payload.LabID = s.cfg.LabID
	payload.Hostname = s.cfg.Hostname

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	const maxRetries = 3
	backoff := 2 * time.Second

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff + time.Duration(rand.Int63n(int64(backoff/2)))):
				backoff *= 2 // exponential with jitter: ~2-3s, ~4-6s, ~8-12s
			}
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
			lastErr = fmt.Errorf("sending metrics: %w", err)
			continue // retry on network error
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
			return nil // success
		}

		lastErr = fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(respBody))

		// Don't retry client errors (4xx) — they won't succeed on retry
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return lastErr
		}
		// Retry on 5xx (server errors)
	}

	return fmt.Errorf("after %d retries: %w", maxRetries, lastErr)
}
