package collector

import (
	"context"
	"runtime"
	"sort"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// SystemMetrics contains system-level metrics.
type SystemMetrics struct {
	Hostname     string          `json:"hostname"`
	OS           string          `json:"os"`
	Platform     string          `json:"platform"`
	Uptime       uint64          `json:"uptime_seconds"`
	CPU          CPUMetrics      `json:"cpu"`
	Memory       MemoryMetrics   `json:"memory"`
	Disk         []DiskMetrics   `json:"disk"`
	Network      []NetMetrics    `json:"network"`
	LoadAverage  LoadMetrics     `json:"load_average"`
	Temperatures []TempMetric    `json:"temperatures"`
	Processes    []ProcessMetric `json:"processes"`
}

type CPUMetrics struct {
	Count        int       `json:"count"`
	UsagePercent []float64 `json:"usage_percent"`
	TotalPercent float64   `json:"total_percent"`
}

type MemoryMetrics struct {
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
	SwapTotalBytes uint64  `json:"swap_total_bytes"`
	SwapUsedBytes  uint64  `json:"swap_used_bytes"`
}

type DiskMetrics struct {
	Mountpoint  string  `json:"mountpoint"`
	Device      string  `json:"device"`
	Fstype      string  `json:"fstype"`
	TotalBytes  uint64  `json:"total_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

type NetMetrics struct {
	Interface string `json:"interface"`
	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
}

type LoadMetrics struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

// TempMetric holds a single temperature sensor reading.
type TempMetric struct {
	SensorKey   string  `json:"sensor_key"`
	Temperature float64 `json:"temperature_celsius"`
	High        float64 `json:"high_threshold_celsius"`
	Critical    float64 `json:"critical_threshold_celsius"`
}

// ProcessMetric holds metrics for a single process.
type ProcessMetric struct {
	PID           int32   `json:"pid"`
	Name          string  `json:"name"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float32 `json:"memory_percent"`
	MemoryBytes   uint64  `json:"memory_bytes"`
	Status        string  `json:"status"`
	Username      string  `json:"username"`
}

// SystemCollector gathers system metrics.
type SystemCollector struct{}

// NewSystem creates a new system metrics collector.
func NewSystem() *SystemCollector {
	return &SystemCollector{}
}

func (s *SystemCollector) Name() string { return "system" }

func (s *SystemCollector) Collect(ctx context.Context) (interface{}, error) {
	metrics := SystemMetrics{
		OS: runtime.GOOS,
	}

	// Host info
	if info, err := host.InfoWithContext(ctx); err == nil {
		metrics.Hostname = info.Hostname
		metrics.Platform = info.Platform
		metrics.Uptime = info.Uptime
	}

	// CPU
	metrics.CPU.Count = runtime.NumCPU()
	if percents, err := cpu.PercentWithContext(ctx, time.Second, true); err == nil {
		metrics.CPU.UsagePercent = percents
		var total float64
		for _, p := range percents {
			total += p
		}
		if len(percents) > 0 {
			metrics.CPU.TotalPercent = total / float64(len(percents))
		}
	}

	// Memory
	if vmem, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		metrics.Memory = MemoryMetrics{
			TotalBytes:     vmem.Total,
			UsedBytes:      vmem.Used,
			AvailableBytes: vmem.Available,
			UsedPercent:    vmem.UsedPercent,
		}
	}
	if swap, err := mem.SwapMemoryWithContext(ctx); err == nil {
		metrics.Memory.SwapTotalBytes = swap.Total
		metrics.Memory.SwapUsedBytes = swap.Used
	}

	// Disk
	if partitions, err := disk.PartitionsWithContext(ctx, false); err == nil {
		for _, p := range partitions {
			if usage, err := disk.UsageWithContext(ctx, p.Mountpoint); err == nil {
				metrics.Disk = append(metrics.Disk, DiskMetrics{
					Mountpoint:  p.Mountpoint,
					Device:      p.Device,
					Fstype:      p.Fstype,
					TotalBytes:  usage.Total,
					UsedBytes:   usage.Used,
					FreeBytes:   usage.Free,
					UsedPercent: usage.UsedPercent,
				})
			}
		}
	}

	// Network
	if counters, err := net.IOCountersWithContext(ctx, true); err == nil {
		for _, c := range counters {
			if c.Name == "lo" {
				continue
			}
			metrics.Network = append(metrics.Network, NetMetrics{
				Interface: c.Name,
				BytesSent: c.BytesSent,
				BytesRecv: c.BytesRecv,
			})
		}
	}

	// Load average
	if avg, err := load.AvgWithContext(ctx); err == nil {
		metrics.LoadAverage = LoadMetrics{
			Load1:  avg.Load1,
			Load5:  avg.Load5,
			Load15: avg.Load15,
		}
	}

	// Temperatures
	if temps, err := host.SensorsTemperaturesWithContext(ctx); err == nil {
		for _, t := range temps {
			metrics.Temperatures = append(metrics.Temperatures, TempMetric{
				SensorKey:   t.SensorKey,
				Temperature: t.Temperature,
				High:        t.High,
				Critical:    t.Critical,
			})
		}
	}
	if metrics.Temperatures == nil {
		metrics.Temperatures = []TempMetric{}
	}

	// Top 10 processes by CPU usage
	metrics.Processes = collectTopProcesses(ctx, 10)

	return metrics, nil
}

// collectTopProcesses returns the top N processes sorted by CPU usage (descending).
func collectTopProcesses(ctx context.Context, n int) []ProcessMetric {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return []ProcessMetric{}
	}

	var procMetrics []ProcessMetric
	for _, p := range procs {
		name, err := p.NameWithContext(ctx)
		if err != nil {
			continue
		}

		cpuPct, err := p.CPUPercentWithContext(ctx)
		if err != nil {
			continue
		}

		memPct, err := p.MemoryPercentWithContext(ctx)
		if err != nil {
			continue
		}

		memInfo, _ := p.MemoryInfoWithContext(ctx)
		var memBytes uint64
		if memInfo != nil {
			memBytes = memInfo.RSS
		}

		statusSlice, _ := p.StatusWithContext(ctx)
		status := ""
		if len(statusSlice) > 0 {
			status = statusSlice[0]
		}

		username, _ := p.UsernameWithContext(ctx)

		procMetrics = append(procMetrics, ProcessMetric{
			PID:           p.Pid,
			Name:          name,
			CPUPercent:    cpuPct,
			MemoryPercent: memPct,
			MemoryBytes:   memBytes,
			Status:        status,
			Username:      username,
		})
	}

	// Sort by CPU usage descending
	sort.Slice(procMetrics, func(i, j int) bool {
		return procMetrics[i].CPUPercent > procMetrics[j].CPUPercent
	})

	// Take top N
	if len(procMetrics) > n {
		procMetrics = procMetrics[:n]
	}

	return procMetrics
}
