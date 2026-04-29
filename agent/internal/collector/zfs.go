package collector

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ZFSMetrics holds ZFS pool health data.
type ZFSMetrics struct {
	Pools []ZFSPool `json:"pools"`
	Error string    `json:"error,omitempty"`
}

// ZFSPool represents one ZFS pool's health.
type ZFSPool struct {
	Name         string  `json:"name"`
	Health       string  `json:"health"`          // ONLINE, DEGRADED, FAULTED, etc.
	SizeBytes    int64   `json:"size_bytes"`
	UsedBytes    int64   `json:"used_bytes"`
	FreeBytes    int64   `json:"free_bytes"`
	UsedPercent  float64 `json:"used_percent"`
	Fragmentation int    `json:"fragmentation"`    // percentage
	LastScrub    string  `json:"last_scrub"`       // human-readable time since last scrub
	ScrubErrors  int     `json:"scrub_errors"`
	ReadErrors   int     `json:"read_errors"`
	WriteErrors  int     `json:"write_errors"`
	CksumErrors  int     `json:"cksum_errors"`
}

// ZFS collects ZFS pool health via zpool (if available).
type ZFS struct {
	binary string // resolved zpool path ("" = disabled)
}

// NewZFS builds a collector. If zpool is not on PATH, returns a no-op collector.
func NewZFS() *ZFS {
	path, err := exec.LookPath("zpool")
	if err != nil {
		return &ZFS{binary: ""}
	}
	return &ZFS{binary: path}
}

func (z *ZFS) Name() string { return "zfs" }

func (z *ZFS) Collect(ctx context.Context) (interface{}, error) {
	metrics := ZFSMetrics{Pools: []ZFSPool{}}
	if z.binary == "" {
		metrics.Error = "zpool not installed"
		return metrics, nil
	}

	// Get pool list with parseable output
	// zpool list -Hp: name, size, alloc, free, ckpoint, expandsz, frag, cap, dedup, health, altroot
	listCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	listOut, err := exec.CommandContext(listCtx, z.binary, "list", "-Hp").Output()
	if err != nil {
		metrics.Error = fmt.Sprintf("zpool list failed: %v", err)
		return metrics, nil
	}

	lines := strings.Split(strings.TrimSpace(string(listOut)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		pool := z.parseLine(line)
		if pool.Name != "" {
			// Get scrub info from zpool status
			z.addScrubInfo(ctx, &pool)
			metrics.Pools = append(metrics.Pools, pool)
		}
	}

	return metrics, nil
}

// parseLine parses one line from "zpool list -Hp"
// Fields: name, size, alloc, free, ckpoint, expandsz, frag, cap, dedup, health, altroot
func (z *ZFS) parseLine(line string) ZFSPool {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return ZFSPool{}
	}

	pool := ZFSPool{
		Name:   fields[0],
		Health: fields[9],
	}

	if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
		pool.SizeBytes = v
	}
	if v, err := strconv.ParseInt(fields[2], 10, 64); err == nil {
		pool.UsedBytes = v
	}
	if v, err := strconv.ParseInt(fields[3], 10, 64); err == nil {
		pool.FreeBytes = v
	}
	// frag field (index 6): might be "-" if not applicable
	frag := strings.TrimSuffix(fields[6], "%")
	if v, err := strconv.Atoi(frag); err == nil {
		pool.Fragmentation = v
	}

	if pool.SizeBytes > 0 {
		pool.UsedPercent = float64(pool.UsedBytes) / float64(pool.SizeBytes) * 100
	}

	return pool
}

// addScrubInfo runs "zpool status <pool>" and parses scrub results.
func (z *ZFS) addScrubInfo(ctx context.Context, pool *ZFSPool) {
	statusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(statusCtx, z.binary, "status", pool.Name).Output()
	if err != nil {
		return
	}

	output := string(out)

	// Parse error counts from the pool line in "zpool status" output.
	// Format:   NAME        STATE     READ WRITE CKSUM
	//           poolname    ONLINE       0     0     0
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) >= 5 && fields[0] == pool.Name {
			if v, err := strconv.Atoi(fields[2]); err == nil {
				pool.ReadErrors = v
			}
			if v, err := strconv.Atoi(fields[3]); err == nil {
				pool.WriteErrors = v
			}
			if v, err := strconv.Atoi(fields[4]); err == nil {
				pool.CksumErrors = v
			}
			break
		}
	}

	// Parse scrub status
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "scan:") {
			if strings.Contains(trimmed, "scrub repaired") {
				// Extract "on Sun Apr 27 12:00:00 2026" from the line
				if idx := strings.Index(trimmed, " on "); idx != -1 {
					pool.LastScrub = strings.TrimSpace(trimmed[idx+4:])
				}
				// Extract error count from "with 0 errors"
				if idx := strings.Index(trimmed, "with "); idx != -1 {
					errPart := trimmed[idx+5:]
					if spIdx := strings.Index(errPart, " "); spIdx != -1 {
						if v, err := strconv.Atoi(errPart[:spIdx]); err == nil {
							pool.ScrubErrors = v
						}
					}
				}
			} else if strings.Contains(trimmed, "scrub in progress") {
				pool.LastScrub = "in progress"
			} else if strings.Contains(trimmed, "none requested") {
				pool.LastScrub = "never"
			}
			break
		}
	}
}
