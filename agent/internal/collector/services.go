package collector

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/labwatch-dev/labwatch/internal/config"
)

// ServiceMetrics contains service health check results.
type ServiceMetrics struct {
	Services []ServiceStatus `json:"services"`
}

type ServiceStatus struct {
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	Endpoint     string  `json:"endpoint"`
	Healthy      bool    `json:"healthy"`
	ResponseTime float64 `json:"response_time_ms"`
	StatusCode   int     `json:"status_code,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// ServiceChecker monitors configured services.
type ServiceChecker struct {
	services []config.ServiceConfig
}

// NewServiceChecker creates a new service health checker.
func NewServiceChecker(services []config.ServiceConfig) *ServiceChecker {
	return &ServiceChecker{services: services}
}

func (s *ServiceChecker) Name() string { return "services" }

func (s *ServiceChecker) Collect(ctx context.Context) (interface{}, error) {
	metrics := ServiceMetrics{}

	for _, svc := range s.services {
		status := ServiceStatus{
			Name:     svc.Name,
			Type:     svc.Type,
			Endpoint: svc.Endpoint,
		}

		timeout := 5 * time.Second
		if svc.Timeout != "" {
			if d, err := time.ParseDuration(svc.Timeout); err == nil {
				timeout = d
			}
		}
		// Cap timeout to prevent config mistakes from blocking collection
		if timeout > 30*time.Second {
			timeout = 30 * time.Second
		}

		start := time.Now()

		switch svc.Type {
		case "http":
			status = checkHTTP(svc, timeout, start)
		case "tcp":
			status = checkTCP(svc, timeout, start)
		default:
			status.Error = fmt.Sprintf("unknown check type: %s", svc.Type)
		}

		metrics.Services = append(metrics.Services, status)
	}

	return metrics, nil
}

func checkHTTP(svc config.ServiceConfig, timeout time.Duration, start time.Time) ServiceStatus {
	status := ServiceStatus{
		Name:     svc.Name,
		Type:     svc.Type,
		Endpoint: svc.Endpoint,
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("stopped after 3 redirects")
			}
			return nil
		},
	}
	resp, err := client.Get(svc.Endpoint)
	status.ResponseTime = float64(time.Since(start).Milliseconds())

	if err != nil {
		status.Error = err.Error()
		return status
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	status.StatusCode = resp.StatusCode
	status.Healthy = resp.StatusCode >= 200 && resp.StatusCode < 400

	return status
}

func checkTCP(svc config.ServiceConfig, timeout time.Duration, start time.Time) ServiceStatus {
	status := ServiceStatus{
		Name:     svc.Name,
		Type:     svc.Type,
		Endpoint: svc.Endpoint,
	}

	conn, err := net.DialTimeout("tcp", svc.Endpoint, timeout)
	status.ResponseTime = float64(time.Since(start).Milliseconds())

	if err != nil {
		status.Error = err.Error()
		return status
	}
	conn.Close()

	status.Healthy = true
	return status
}
