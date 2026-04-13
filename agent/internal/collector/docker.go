package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// DockerMetrics contains Docker container metrics.
type DockerMetrics struct {
	Running    int               `json:"running"`
	Stopped    int               `json:"stopped"`
	Total      int               `json:"total"`
	Containers []ContainerMetric `json:"containers"`
}

type ContainerMetric struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Image         string  `json:"image"`
	State         string  `json:"state"`
	Status        string  `json:"status"`
	RestartCount  int     `json:"restart_count"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsage   uint64  `json:"memory_usage_bytes"`
	MemoryLimit   uint64  `json:"memory_limit_bytes"`
	MemoryPercent float64 `json:"memory_percent"`
}

// DockerCollector gathers Docker container metrics.
type DockerCollector struct {
	client *client.Client
}

// NewDocker creates a new Docker collector.
func NewDocker(socketPath string) (*DockerCollector, error) {
	opts := []client.Opt{
		client.WithAPIVersionNegotiation(),
	}
	if socketPath != "" {
		opts = append(opts, client.WithHost("unix://"+socketPath))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating docker client: %w", err)
	}

	// Test connection with timeout to avoid hanging on unresponsive socket
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if _, err := cli.Ping(pingCtx); err != nil {
		cli.Close()
		return nil, fmt.Errorf("connecting to docker: %w", err)
	}

	return &DockerCollector{client: cli}, nil
}

func (d *DockerCollector) Name() string { return "docker" }

func (d *DockerCollector) Collect(ctx context.Context) (interface{}, error) {
	containers, err := d.client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}

	metrics := DockerMetrics{
		Total: len(containers),
	}

	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		id := c.ID
		if len(id) > 12 {
			id = id[:12]
		}
		cm := ContainerMetric{
			ID:    id,
			Name:  name,
			Image: c.Image,
			State: c.State,
			Status: c.Status,
		}

		if c.State == "running" {
			metrics.Running++

			// Get detailed stats for running containers
			statsResp, err := d.client.ContainerStatsOneShot(ctx, c.ID)
			if err == nil {
				func() {
					defer statsResp.Body.Close()
					var stats types.StatsJSON
					if decErr := json.NewDecoder(statsResp.Body).Decode(&stats); decErr != nil {
						return
					}
					// CPU percent: delta usage / delta system * num CPUs * 100
					cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
					sysDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)
					if sysDelta > 0 && cpuDelta > 0 {
						numCPUs := float64(stats.CPUStats.OnlineCPUs)
						if numCPUs == 0 {
							numCPUs = float64(len(stats.CPUStats.CPUUsage.PercpuUsage))
						}
						if numCPUs == 0 {
							numCPUs = float64(runtime.NumCPU())
						}
						if numCPUs > 0 {
							cm.CPUPercent = (cpuDelta / sysDelta) * numCPUs * 100.0
						}
					}

					// Memory (subtract cache for actual usage)
					cache := uint64(0)
					if stats.MemoryStats.Stats != nil {
						if c, ok := stats.MemoryStats.Stats["cache"]; ok {
							cache = c
						} else if c, ok := stats.MemoryStats.Stats["inactive_file"]; ok {
							cache = c // cgroup v2
						}
					}
					if cache <= stats.MemoryStats.Usage {
						cm.MemoryUsage = stats.MemoryStats.Usage - cache
					} else {
						cm.MemoryUsage = stats.MemoryStats.Usage
					}
					cm.MemoryLimit = stats.MemoryStats.Limit
					if cm.MemoryLimit > 0 {
						cm.MemoryPercent = float64(cm.MemoryUsage) / float64(cm.MemoryLimit) * 100.0
					}
				}()
			}
		} else {
			metrics.Stopped++
		}

		// Get inspect for restart count
		if inspect, err := d.client.ContainerInspect(ctx, c.ID); err == nil {
			cm.RestartCount = inspect.RestartCount
		}

		metrics.Containers = append(metrics.Containers, cm)
	}

	return metrics, nil
}
