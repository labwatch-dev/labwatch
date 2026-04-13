<p align="center">
  <h1 align="center">labwatch</h1>
  <p align="center">
    A lightweight monitoring agent for homelabs.<br>
    Single binary. No dependencies. Outbound-only.
  </p>
</p>

<p align="center">
  <a href="https://github.com/labwatch-dev/labwatch/releases"><img src="https://img.shields.io/github/v/release/labwatch-dev/labwatch?style=flat-square" alt="Release"></a>
  <a href="https://github.com/labwatch-dev/labwatch/actions"><img src="https://img.shields.io/github/actions/workflow/status/labwatch-dev/labwatch/build.yml?style=flat-square" alt="Build"></a>
  <a href="https://goreportcard.com/report/github.com/labwatch-dev/labwatch"><img src="https://goreportcard.com/badge/github.com/labwatch-dev/labwatch?style=flat-square" alt="Go Report"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <a href="https://labwatch.dev"><img src="https://img.shields.io/badge/docs-labwatch.dev-blue?style=flat-square" alt="Docs"></a>
</p>

---

**labwatch** is a tiny, statically-compiled Go agent that collects system metrics, Docker container stats, and service health data from your homelab nodes and sends them to a [Labwatch server](https://labwatch.dev) over HTTPS.

It is designed for the self-hosted and homelab community: privacy-first, zero dependencies, runs anywhere Linux runs, and never opens an inbound port.

## Why labwatch?

| | |
|---|---|
| **~8 MB static binary** | No runtime, no interpreters, no package managers. Copy it, run it. |
| **Outbound-only** | The agent POSTs metrics to your server. No ports to open, no attack surface. |
| **Your data, your server** | Metrics go to a Labwatch instance you control. Nothing phones home. |
| **Unprivileged** | Reads from `/proc` and `/sys`. Talks to Docker over its Unix socket. No root required at runtime. |
| **Systemd-native** | Installs as a hardened systemd service with memory limits and filesystem protections. |
| **~1,300 lines of Go** | Small enough to audit in an afternoon. |

## What it collects

### System metrics
- **CPU** -- per-core and aggregate usage percentage, core count
- **Memory** -- total, used, available, swap (bytes and percent)
- **Disk** -- per-mountpoint usage (device, filesystem type, total/used/free)
- **Network** -- per-interface bytes sent and received
- **Load average** -- 1, 5, and 15-minute load averages
- **Host info** -- hostname, OS, platform, uptime

### Docker containers
- Container count (running, stopped, total)
- Per-container: name, image, state, status, restart count
- CPU and memory usage for running containers
- Connects via the Docker socket (configurable path)

### Service health checks
- **HTTP** -- GET request, reports status code and response time, healthy if 2xx/3xx
- **TCP** -- connection test to host:port, reports response time
- Configurable timeouts per service

## Quick start

### One-liner install

```bash
curl -fsSL https://labwatch.dev/install.sh | sudo bash
```

This downloads the correct binary for your architecture (amd64, arm64, or armv7), installs it to `/usr/local/bin/labwatch`, creates a config file at `/etc/labwatch/config.yaml`, and sets up a systemd service.

### Manual install

```bash
# Download the binary (replace ARCH with amd64, arm64, or armv7)
curl -fsSL -o /usr/local/bin/labwatch https://labwatch.dev/download/labwatch-linux-ARCH
chmod +x /usr/local/bin/labwatch

# Verify
labwatch --version
```

### Register and start

```bash
# 1. Register the agent with your Labwatch server
labwatch --register

# 2. Add the returned token and lab_id to your config
sudo nano /etc/labwatch/config.yaml

# 3. Enable and start the service
sudo systemctl enable --now labwatch

# 4. Check status
sudo systemctl status labwatch
sudo journalctl -u labwatch -f
```

## Configuration

The agent reads its configuration from `/etc/labwatch/config.yaml` by default. Override with `--config /path/to/config.yaml`.

### Full reference

```yaml
# Labwatch server API endpoint
api_endpoint: "https://labwatch.dev/api/v1"

# Authentication token (obtained via `labwatch --register`)
token: "your-token-here"

# Lab identifier (assigned during registration)
lab_id: "your-lab-id"

# How often to collect and send metrics (minimum: 10s)
interval: 60s

# Hostname override (defaults to system hostname)
# hostname: "my-server"

# Docker container monitoring
docker:
  enabled: true
  socket: "/var/run/docker.sock"

# Service health checks
services:
  # HTTP health check -- healthy if response is 2xx or 3xx
  - name: "Nginx"
    type: "http"
    endpoint: "http://localhost:80"
    timeout: "5s"

  # TCP port check -- healthy if connection succeeds
  - name: "Postgres"
    type: "tcp"
    endpoint: "localhost:5432"
    timeout: "3s"

  # More examples:
  # - name: "Plex"
  #   type: "http"
  #   endpoint: "http://localhost:32400/web"
  #   timeout: "5s"
  #
  # - name: "Pi-hole DNS"
  #   type: "tcp"
  #   endpoint: "localhost:53"
  #   timeout: "2s"
  #
  # - name: "Home Assistant"
  #   type: "http"
  #   endpoint: "http://localhost:8123"
  #   timeout: "5s"
```

### Configuration options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `api_endpoint` | string | `https://labwatch.dev/api/v1` | Labwatch server API URL |
| `token` | string | `""` | Bearer token for authentication |
| `lab_id` | string | `""` | Lab identifier from registration |
| `interval` | duration | `60s` | Collection interval (minimum `10s`) |
| `hostname` | string | system hostname | Override reported hostname |
| `docker.enabled` | bool | `true` | Enable Docker container monitoring |
| `docker.socket` | string | `/var/run/docker.sock` | Path to Docker socket |
| `services` | list | `[]` | Service health checks (see above) |

### Service check types

| Type | Endpoint format | Healthy when |
|------|----------------|--------------|
| `http` | Full URL (`http://host:port/path`) | Status code 200-399 |
| `tcp` | `host:port` | TCP connection succeeds |

## Docker socket access

The agent connects to Docker via its Unix socket to collect container metrics. If your user is not in the `docker` group, you have two options:

```bash
# Option A: Add the labwatch service user to the docker group
sudo usermod -aG docker labwatch

# Option B: Set the socket path in config to a rootless Docker socket
docker:
  socket: "/run/user/1000/docker.sock"
```

To disable Docker monitoring entirely, set `docker.enabled: false`.

## Building from source

Requirements: Go 1.23 or later.

```bash
git clone https://github.com/labwatch-dev/labwatch.git
cd agent

# Build
go build -o labwatch ./cmd/labwatch

# Build with version info
go build -ldflags "-s -w -X main.version=0.1.0 -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o labwatch ./cmd/labwatch

# Cross-compile for ARM (Raspberry Pi)
GOOS=linux GOARCH=arm64 go build -o labwatch-linux-arm64 ./cmd/labwatch
GOOS=linux GOARCH=arm GOARM=7 go build -o labwatch-linux-armv7 ./cmd/labwatch
```

The resulting binary is fully static with no external dependencies.

## Systemd service

The installer creates a hardened systemd unit at `/etc/systemd/system/labwatch.service`:

```ini
[Unit]
Description=labwatch monitoring agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/labwatch --config /etc/labwatch/config.yaml
Restart=always
RestartSec=10
MemoryMax=64M

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/labwatch
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

The service enforces a 64 MB memory ceiling and applies systemd sandboxing: no privilege escalation, read-only filesystem (except its config directory), isolated `/tmp`, and no access to home directories.

## Architecture

```
labwatch (~1,300 lines of Go, 9 files)
|
|-- cmd/labwatch/main.go          Entry point, collection loop, signal handling
|
|-- internal/
|   |-- config/config.go          YAML config loading with defaults
|   |-- collector/
|   |   |-- collector.go          Collector interface
|   |   |-- system.go             CPU, memory, disk, network, load
|   |   |-- docker.go             Docker container stats via API
|   |   |-- services.go           HTTP and TCP health checks
|   |   |-- gpu.go                NVIDIA GPU stats via nvidia-smi
|   |   |-- smart.go              Disk SMART health via smartctl
|   |-- transport/transport.go    HTTPS POST to server, registration
```

The agent runs a straightforward collect-and-send loop:

1. On startup (and every `interval`), all enabled collectors run
2. Results are assembled into a single JSON payload
3. The payload is POSTed to the server with a Bearer token
4. On failure, the error is logged and the agent retries on the next interval

The agent uses context-aware cancellation throughout. A `SIGINT` or `SIGTERM` triggers a clean shutdown.

## Supported platforms

| Architecture | Binary name | Tested on |
|---|---|---|
| x86_64 / amd64 | `labwatch-linux-amd64` | Debian, Ubuntu, Proxmox, Arch |
| ARM64 / aarch64 | `labwatch-linux-arm64` | Raspberry Pi 4/5, Oracle Cloud |
| ARMv7 | `labwatch-linux-armv7` | Raspberry Pi 3, older ARM SBCs |

Any Linux distribution with systemd is supported. The binary is statically linked and has no runtime dependencies.

## Contributing

Contributions are welcome. If you have an idea for a new collector, a bug fix, or a documentation improvement, please open an issue or pull request.

```bash
# Clone and build
git clone https://github.com/labwatch-dev/labwatch.git
cd agent
go build ./cmd/labwatch

# Run tests
go test ./...

# Run the agent locally
./labwatch --config config.example.yaml
```

When submitting a pull request:

- Follow the existing code style (standard Go conventions, `gofmt`)
- Add tests for new functionality
- Keep collectors self-contained: one file in `internal/collector/`, implementing the `Collector` interface
- Update `config.example.yaml` if you add new config options

### Adding a new collector

Implement the `Collector` interface:

```go
type Collector interface {
    Name() string
    Collect(ctx context.Context) (interface{}, error)
}
```

Your collector's `Name()` becomes the key in the JSON payload. Return any struct from `Collect()` and it will be serialized automatically.

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <a href="https://labwatch.dev">Website</a> &middot;
  <a href="https://labwatch.dev/docs">Docs</a> &middot;
  <a href="https://github.com/labwatch-dev/labwatch/issues">Issues</a>
</p>
