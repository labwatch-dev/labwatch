// Package config handles labwatch agent configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all agent configuration.
type Config struct {
	// API endpoint URL
	APIEndpoint string `yaml:"api_endpoint"`

	// Agent authentication token (obtained during registration)
	Token string `yaml:"token"`

	// Admin secret (used only during registration)
	AdminSecret string `yaml:"admin_secret"`

	// Collection interval
	Interval time.Duration `yaml:"interval"`

	// Lab identifier (auto-generated on first run)
	LabID string `yaml:"lab_id"`

	// Hostname override (defaults to os.Hostname)
	Hostname string `yaml:"hostname"`

	// Docker collector settings
	Docker DockerConfig `yaml:"docker"`

	// GPU collector settings
	GPU GPUConfig `yaml:"gpu"`

	// S.M.A.R.T. disk health settings
	SMART SMARTConfig `yaml:"smart"`

	// ZFS pool health settings
	ZFS ZFSConfig `yaml:"zfs"`

	// Services to monitor
	Services []ServiceConfig `yaml:"services"`
}

// DockerConfig controls Docker container monitoring.
type DockerConfig struct {
	Enabled bool   `yaml:"enabled"`
	Socket  string `yaml:"socket"`
}

// GPUConfig controls NVIDIA GPU monitoring.
type GPUConfig struct {
	Enabled bool `yaml:"enabled"`
}

// SMARTConfig controls S.M.A.R.T. disk health collection.
// Requires smartctl (smartmontools) installed and readable by the agent user.
type SMARTConfig struct {
	Enabled bool `yaml:"enabled"`
}

// ZFSConfig controls ZFS pool health collection.
// Requires zpool (ZFS utilities) installed.
type ZFSConfig struct {
	Enabled bool `yaml:"enabled"`
}

// ServiceConfig defines a service to monitor.
type ServiceConfig struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`     // "http", "tcp", "systemd"
	Endpoint string `yaml:"endpoint"` // URL for http, host:port for tcp, unit name for systemd
	Timeout  string `yaml:"timeout"`
}

// Defaults returns a config with sensible defaults.
func Defaults() *Config {
	hostname, _ := os.Hostname()
	return &Config{
		APIEndpoint: "https://labwatch.dev/api/v1",
		Interval:    60 * time.Second,
		Hostname:    hostname,
		Docker: DockerConfig{
			Enabled: true,
			Socket:  "/var/run/docker.sock",
		},
		GPU: GPUConfig{
			Enabled: true,
		},
		SMART: SMARTConfig{
			Enabled: true,
		},
		ZFS: ZFSConfig{
			Enabled: true,
		},
	}
}

// Load reads config from a YAML file, falling back to defaults.
func Load(path string) (*Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file — use defaults
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.Interval < 10*time.Second {
		cfg.Interval = 10 * time.Second
	}

	return cfg, nil
}
