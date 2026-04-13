package collector

import (
	"context"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

// GPUMetrics contains GPU-level metrics from NVIDIA GPUs.
type GPUMetrics struct {
	Count   int         `json:"count"`
	Devices []GPUDevice `json:"devices"`
}

// GPUDevice holds metrics for a single GPU.
type GPUDevice struct {
	Index              int       `json:"index"`
	Name               string    `json:"name"`
	UtilizationPercent float64   `json:"utilization_percent"`
	Memory             GPUMemory `json:"memory"`
	TemperatureCelsius float64   `json:"temperature_celsius"`
	PowerWatts         float64   `json:"power_watts"`
	PowerLimitWatts    float64   `json:"power_limit_watts"`
	FanSpeedPercent    float64   `json:"fan_speed_percent"`
}

// GPUMemory holds GPU memory metrics.
type GPUMemory struct {
	TotalBytes  uint64  `json:"total_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

// GPUCollector gathers NVIDIA GPU metrics via nvidia-smi.
type GPUCollector struct{}

// NewGPU creates a new GPU metrics collector.
func NewGPU() *GPUCollector {
	return &GPUCollector{}
}

func (g *GPUCollector) Name() string { return "gpu" }

func (g *GPUCollector) Collect(ctx context.Context) (interface{}, error) {
	metrics := GPUMetrics{}

	// Check if nvidia-smi is available
	smiPath, err := exec.LookPath("nvidia-smi")
	if err != nil {
		// No NVIDIA driver/GPU — graceful degradation
		return metrics, nil
	}

	cmd := exec.CommandContext(ctx, smiPath,
		"--query-gpu=index,name,utilization.gpu,memory.total,memory.used,memory.free,temperature.gpu,power.draw,power.limit,fan.speed",
		"--format=csv,noheader,nounits",
	)

	output, err := cmd.Output()
	if err != nil {
		// nvidia-smi failed (driver issue, no GPU, etc.) — graceful degradation
		log.Printf("GPU collector: nvidia-smi failed: %v", err)
		return metrics, nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		device, err := parseGPULine(line)
		if err != nil {
			log.Printf("GPU collector: failed to parse line %q: %v", line, err)
			continue
		}

		metrics.Devices = append(metrics.Devices, device)
	}

	metrics.Count = len(metrics.Devices)
	return metrics, nil
}

// parseGPULine parses a single CSV line from nvidia-smi output.
// Expected fields: index, name, utilization.gpu, memory.total, memory.used, memory.free,
//
//	temperature.gpu, power.draw, power.limit, fan.speed
func parseGPULine(line string) (GPUDevice, error) {
	fields := strings.Split(line, ", ")
	if len(fields) < 10 {
		// Try splitting with just comma (some nvidia-smi versions don't add space)
		fields = strings.Split(line, ",")
	}

	// Trim whitespace from all fields
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}

	if len(fields) < 10 {
		return GPUDevice{}, &parseError{"expected 10 fields, got " + strconv.Itoa(len(fields))}
	}

	dev := GPUDevice{}

	// index
	if v, err := strconv.Atoi(fields[0]); err == nil {
		dev.Index = v
	}

	// name
	dev.Name = fields[1]

	// utilization.gpu (percent)
	dev.UtilizationPercent = parseFloat(fields[2])

	// memory.total (MiB from nvidia-smi) -> bytes
	memTotalMiB := parseFloat(fields[3])
	memUsedMiB := parseFloat(fields[4])
	memFreeMiB := parseFloat(fields[5])

	dev.Memory.TotalBytes = mibToBytes(memTotalMiB)
	dev.Memory.UsedBytes = mibToBytes(memUsedMiB)
	dev.Memory.FreeBytes = mibToBytes(memFreeMiB)

	if memTotalMiB > 0 {
		dev.Memory.UsedPercent = (memUsedMiB / memTotalMiB) * 100.0
	}

	// temperature.gpu (celsius)
	dev.TemperatureCelsius = parseFloat(fields[6])

	// power.draw (watts)
	dev.PowerWatts = parseFloat(fields[7])

	// power.limit (watts)
	dev.PowerLimitWatts = parseFloat(fields[8])

	// fan.speed (percent)
	dev.FanSpeedPercent = parseFloat(fields[9])

	return dev, nil
}

// parseFloat parses a string to float64, returning 0 on failure.
// Handles nvidia-smi "[Not Supported]" and "[N/A]" gracefully.
func parseFloat(s string) float64 {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		return 0
	}
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// mibToBytes converts MiB (mebibytes) to bytes.
func mibToBytes(mib float64) uint64 {
	if mib <= 0 {
		return 0
	}
	return uint64(mib * 1024 * 1024)
}

// parseError is a simple error type for parse failures.
type parseError struct {
	msg string
}

func (e *parseError) Error() string {
	return "gpu parse error: " + e.msg
}
