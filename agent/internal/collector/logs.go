// Log collector for journald and Docker container logs.
package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// LogEntry represents a single log line to be shipped to the server.
type LogEntry struct {
	Timestamp string `json:"ts"`
	Source    string `json:"source"`
	Level    string `json:"level"`
	Message  string `json:"message"`
	Unit     string `json:"unit,omitempty"`
}

// LogsConfig controls log collection behavior.
type LogsConfig struct {
	Enabled        bool     `yaml:"enabled"`
	Journald       bool     `yaml:"journald"`
	Docker         bool     `yaml:"docker"`
	Files          []string `yaml:"files"`
	LevelFilter    string   `yaml:"level_filter"`
	MaxLinesPerPush int    `yaml:"max_lines_per_push"`
	DockerSocket   string  `yaml:"docker_socket"`
}

// LogCollector gathers log entries from journald and Docker.
type LogCollector struct {
	cfg        LogsConfig
	mu         sync.Mutex
	lastCursor string    // journald cursor for incremental reads
	lastTime   time.Time // fallback timestamp for --since
}

// NewLogCollector creates a new log collector.
func NewLogCollector(cfg LogsConfig) *LogCollector {
	if cfg.MaxLinesPerPush <= 0 {
		cfg.MaxLinesPerPush = 100
	}
	if cfg.LevelFilter == "" {
		cfg.LevelFilter = "warn"
	}
	if cfg.DockerSocket == "" {
		cfg.DockerSocket = "/var/run/docker.sock"
	}
	return &LogCollector{
		cfg:      cfg,
		lastTime: time.Now().UTC(),
	}
}

// CollectLogs gathers log entries since the last collection. Not a standard Collector
// because logs go to a different API endpoint.
func (lc *LogCollector) CollectLogs(ctx context.Context) ([]LogEntry, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	var entries []LogEntry
	maxLines := lc.cfg.MaxLinesPerPush

	if lc.cfg.Journald {
		jEntries, newCursor, err := lc.collectJournald(ctx, maxLines)
		if err == nil {
			entries = append(entries, jEntries...)
			if newCursor != "" {
				lc.lastCursor = newCursor
			}
		}
	}

	remaining := maxLines - len(entries)
	if remaining > 0 && lc.cfg.Docker {
		dEntries, err := lc.collectDocker(ctx, remaining)
		if err == nil {
			entries = append(entries, dEntries...)
		}
	}

	lc.lastTime = time.Now().UTC()

	// Apply level filter
	minLevel := levelPriority(lc.cfg.LevelFilter)
	var filtered []LogEntry
	for _, e := range entries {
		if levelPriority(e.Level) >= minLevel {
			filtered = append(filtered, e)
		}
	}

	// Cap at max lines
	if len(filtered) > maxLines {
		filtered = filtered[:maxLines]
	}

	return filtered, nil
}

// collectJournald reads new entries from systemd journal.
func (lc *LogCollector) collectJournald(ctx context.Context, maxLines int) ([]LogEntry, string, error) {
	// Check if journalctl is available
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, "", fmt.Errorf("journalctl not found: %w", err)
	}

	args := []string{"--no-pager", "-o", "json", fmt.Sprintf("-n%d", maxLines)}

	if lc.lastCursor != "" {
		args = append(args, "--after-cursor="+lc.lastCursor)
	} else {
		since := lc.lastTime.Format("2006-01-02 15:04:05")
		args = append(args, "--since="+since)
	}

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, "", fmt.Errorf("journalctl failed: %w", err)
	}

	var entries []LogEntry
	var lastCursor string

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}

		var jEntry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &jEntry); err != nil {
			continue
		}

		// Extract fields
		msg := getString(jEntry, "MESSAGE")
		if msg == "" {
			continue
		}

		unit := getString(jEntry, "_SYSTEMD_UNIT")
		priority := getString(jEntry, "PRIORITY")
		ts := getString(jEntry, "__REALTIME_TIMESTAMP")
		cursor := getString(jEntry, "__CURSOR")

		if cursor != "" {
			lastCursor = cursor
		}

		// Convert realtime timestamp (microseconds) to ISO8601
		var isoTS string
		if ts != "" {
			var usec int64
			fmt.Sscanf(ts, "%d", &usec)
			isoTS = time.Unix(0, usec*1000).UTC().Format(time.RFC3339)
		} else {
			isoTS = time.Now().UTC().Format(time.RFC3339)
		}

		entries = append(entries, LogEntry{
			Timestamp: isoTS,
			Source:    "journald",
			Level:     journaldPriorityToLevel(priority),
			Message:   truncate(msg, 4096),
			Unit:      unit,
		})
	}

	return entries, lastCursor, nil
}

// collectDocker reads recent logs from running Docker containers.
func (lc *LogCollector) collectDocker(ctx context.Context, maxLines int) ([]LogEntry, error) {
	// Check if docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker not found: %w", err)
	}

	// List running containers
	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.ID}} {{.Names}}", "--no-trunc")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}

	since := lc.lastTime.Format(time.RFC3339)
	var entries []LogEntry
	linesPerContainer := maxLines / max(1, strings.Count(strings.TrimSpace(string(out)), "\n")+1)
	if linesPerContainer < 10 {
		linesPerContainer = 10
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		containerID := parts[0]
		containerName := parts[1]

		logCmd := exec.CommandContext(ctx, "docker", "logs",
			"--since", since,
			"--timestamps",
			"--tail", fmt.Sprintf("%d", linesPerContainer),
			containerID,
		)
		// docker logs writes to both stdout and stderr
		logOut, _ := logCmd.CombinedOutput()

		for _, logLine := range strings.Split(strings.TrimSpace(string(logOut)), "\n") {
			if logLine == "" {
				continue
			}

			ts, msg := parseDockerLogLine(logLine)
			if msg == "" {
				continue
			}

			entries = append(entries, LogEntry{
				Timestamp: ts,
				Source:    "docker:" + containerName,
				Level:     guessLogLevel(msg),
				Message:   truncate(msg, 4096),
			})

			if len(entries) >= maxLines {
				return entries, nil
			}
		}
	}

	return entries, nil
}

// parseDockerLogLine extracts timestamp and message from a Docker log line.
// Docker --timestamps format: "2006-01-02T15:04:05.999999999Z message"
func parseDockerLogLine(line string) (string, string) {
	if len(line) > 30 && (line[4] == '-' || line[10] == 'T') {
		spaceIdx := strings.IndexByte(line, ' ')
		if spaceIdx > 20 && spaceIdx < 40 {
			return line[:spaceIdx], strings.TrimSpace(line[spaceIdx+1:])
		}
	}
	return time.Now().UTC().Format(time.RFC3339), line
}

// guessLogLevel infers a log level from message content.
func guessLogLevel(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "error") || strings.Contains(lower, "fatal") ||
		strings.Contains(lower, "panic") || strings.Contains(lower, "crit"):
		return "error"
	case strings.Contains(lower, "warn"):
		return "warn"
	case strings.Contains(lower, "debug") || strings.Contains(lower, "trace"):
		return "debug"
	default:
		return "info"
	}
}

// journaldPriorityToLevel maps syslog priority to our level.
func journaldPriorityToLevel(p string) string {
	switch p {
	case "0", "1", "2", "3": // emerg, alert, crit, err
		return "error"
	case "4": // warning
		return "warn"
	case "7": // debug
		return "debug"
	default: // 5=notice, 6=info
		return "info"
	}
}

// levelPriority returns a numeric priority for level filtering.
func levelPriority(level string) int {
	switch strings.ToLower(level) {
	case "debug":
		return 0
	case "info":
		return 1
	case "warn", "warning":
		return 2
	case "error", "fatal", "critical":
		return 3
	default:
		return 1
	}
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
