package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// SMARTMetrics holds S.M.A.R.T. disk health data for all detected block devices.
type SMARTMetrics struct {
	Devices []DiskHealth `json:"devices"`
	Error   string       `json:"error,omitempty"`
}

// DiskHealth summarises one block devices S.M.A.R.T. status.
type DiskHealth struct {
	Device            string  `json:"device"`           // e.g. "/dev/sda"
	Model             string  `json:"model,omitempty"`  // device model
	Serial            string  `json:"serial,omitempty"` // last 6 chars only (privacy)
	Type              string  `json:"type,omitempty"`   // "sat", "nvme", ...
	Healthy           bool    `json:"healthy"`          // smart_status.passed
	TemperatureC      float64 `json:"temperature_c,omitempty"`
	PowerOnHours      int64   `json:"power_on_hours,omitempty"`
	ReallocatedSector int64   `json:"reallocated_sector_ct,omitempty"`
	PendingSector     int64   `json:"pending_sector_ct,omitempty"`
	Error             string  `json:"error,omitempty"`
}

// SMART collects disk health via smartctl (if available).
type SMART struct {
	binary string // resolved smartctl path ("" = disabled)
}

// NewSMART builds a collector. If smartctl is not on PATH, the collector
// still works but every Collect call returns a skip-marker instead of blowing up.
func NewSMART() *SMART {
	path, err := exec.LookPath("smartctl")
	if err != nil {
		return &SMART{binary: ""}
	}
	return &SMART{binary: path}
}

func (s *SMART) Name() string { return "smart" }

func (s *SMART) Collect(ctx context.Context) (interface{}, error) {
	metrics := SMARTMetrics{Devices: []DiskHealth{}}
	if s.binary == "" {
		metrics.Error = "smartctl not installed"
		return metrics, nil
	}

	// Phase 1: scan for devices
	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	scanOut, err := exec.CommandContext(scanCtx, s.binary, "--scan", "-j").Output()
	if err != nil {
		metrics.Error = fmt.Sprintf("scan failed: %v", err)
		return metrics, nil
	}

	var scanResp struct {
		Devices []struct {
			Name     string `json:"name"`
			DevType  string `json:"type"`
			InfoName string `json:"info_name"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(scanOut, &scanResp); err != nil {
		metrics.Error = fmt.Sprintf("scan parse: %v", err)
		return metrics, nil
	}

	// Phase 2: query each device
	for _, dev := range scanResp.Devices {
		d := s.queryDevice(ctx, dev.Name, dev.DevType)
		metrics.Devices = append(metrics.Devices, d)
	}
	return metrics, nil
}

// queryDevice runs "smartctl -a -j -d <type> <dev>" and extracts the subset we care about.
func (s *SMART) queryDevice(ctx context.Context, name, devType string) DiskHealth {
	// Healthy defaults to true — we only flag a disk as failing when smartctl
	// explicitly returns smart_status.passed == false. A missing/null
	// smart_status (common when SATA disks are queried via -d scsi on modern
	// kernels) must not be treated as a failure — see queryDevice retry logic.
	h := DiskHealth{Device: name, Type: devType, Healthy: true}
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	buildArgs := func(dt string) []string {
		a := []string{"-a", "-j"}
		if dt != "" {
			a = append(a, "-d", dt)
		}
		return append(a, name)
	}

	runSmartctl := func(dt string) (map[string]interface{}, error) {
		out, rerr := exec.CommandContext(qCtx, s.binary, buildArgs(dt)...).Output()
		// smartctl returns non-zero for bitfield warnings; JSON is still valid.
		var r map[string]interface{}
		if jerr := json.Unmarshal(out, &r); jerr != nil {
			if rerr != nil {
				return nil, fmt.Errorf("smartctl failed: %w", rerr)
			}
			return nil, fmt.Errorf("parse: %w", jerr)
		}
		return r, nil
	}

	resp, rerr := runSmartctl(devType)
	if rerr != nil {
		h.Error = rerr.Error()
		return h
	}

	// SATA-over-SCSI retry: modern Linux kernels expose SATA disks through
	// the SCSI subsystem, so smartctl --scan reports them as type "scsi".
	// Querying with -d scsi works for the basic identify but cannot read the
	// ATA SMART log, so smart_status and ata_smart_attributes come back empty.
	// Retry with -d sat to get the real SMART data.
	if devType == "scsi" && len(name) >= 7 && name[:7] == "/dev/sd" {
		if _, ok := resp["smart_status"].(map[string]interface{}); !ok {
			if retry, rerr2 := runSmartctl("sat"); rerr2 == nil {
				if _, ok2 := retry["smart_status"].(map[string]interface{}); ok2 {
					resp = retry
					h.Type = "sat"
				}
			}
		}
	}

	// --- model / serial ---
	if m, ok := resp["model_name"].(string); ok {
		h.Model = m
	}
	if sn, ok := resp["serial_number"].(string); ok {
		// last 6 chars only — avoid exporting the full serial
		if len(sn) > 6 {
			h.Serial = "..." + sn[len(sn)-6:]
		} else {
			h.Serial = sn
		}
	}

	// --- overall health ---
	if ss, ok := resp["smart_status"].(map[string]interface{}); ok {
		if passed, ok := ss["passed"].(bool); ok {
			h.Healthy = passed
		}
	}

	// --- temperature ---
	if t, ok := resp["temperature"].(map[string]interface{}); ok {
		if cur, ok := t["current"].(float64); ok {
			h.TemperatureC = cur
		}
	}

	// --- power_on_time ---
	if pt, ok := resp["power_on_time"].(map[string]interface{}); ok {
		if hours, ok := pt["hours"].(float64); ok {
			h.PowerOnHours = int64(hours)
		}
	}

	// --- SATA attributes (ATA only) ---
	if ata, ok := resp["ata_smart_attributes"].(map[string]interface{}); ok {
		if table, ok := ata["table"].([]interface{}); ok {
			for _, entry := range table {
				attr, ok := entry.(map[string]interface{})
				if !ok {
					continue
				}
				id, _ := attr["id"].(float64)
				rawVal := int64(0)
				if raw, ok := attr["raw"].(map[string]interface{}); ok {
					if v, ok := raw["value"].(float64); ok {
						rawVal = int64(v)
					}
				}
				switch int(id) {
				case 5: // Reallocated_Sector_Ct
					h.ReallocatedSector = rawVal
				case 197: // Current_Pending_Sector
					h.PendingSector = rawVal
				}
			}
		}
	}

	// --- NVMe log (nvme_smart_health_information_log) ---
	if nvme, ok := resp["nvme_smart_health_information_log"].(map[string]interface{}); ok {
		if t, ok := nvme["temperature"].(float64); ok && h.TemperatureC == 0 {
			h.TemperatureC = t
		}
		if mu, ok := nvme["media_errors"].(float64); ok {
			h.ReallocatedSector = int64(mu) // NVMe equivalent exposure
		}
	}

	return h
}
