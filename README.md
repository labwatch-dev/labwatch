# labwatch

Smart monitoring for homelabs. A lightweight Go agent and intelligence server that understands your infrastructure.

## What it does

labwatch collects system metrics, Docker container status, and service health from every node in your homelab. It stores everything in SQLite, runs rule-based analysis, and generates plain-English intelligence digests about your infrastructure.

**Features:**
- **System metrics** — CPU, memory, disk, load average, network, uptime with inline sparklines
- **Docker monitoring** — container health, restart loops, resource usage
- **Service discovery** — auto-detects Docker, SSH, HTTP, databases, Proxmox, Grafana, Prometheus
- **GPU monitoring** — NVIDIA GPU stats via nvidia-smi
- **Smart alerts** — deduplication, auto-resolution, severity levels (warning/critical)
- **Push notifications** — webhook and ntfy channels for alert delivery
- **Intelligence digests** — narrative health reports with grades (A through C)
- **Natural language queries** — ask "Why is my NAS slow?" and get answers from your metrics
- **Dashboard widgets** — uptime timeline, alert feed, per-node sparklines
- **Drag-and-drop layout** — reorder node cards with mouse or touch (long-press on mobile)
- **Demo mode** — try everything without an account at `/demo`
- **Multi-user accounts** — sign up, pin nodes, set custom alert thresholds
- **i18n** — English, German, French, Spanish, Ukrainian
- **Fleet overview** — all nodes at a glance with health indicators

## Quick start

Two commands to go from zero to monitoring:

### 1. Start the server

```bash
git clone https://github.com/labwatch-dev/labwatch.git && cd labwatch
ADMIN_SECRET=$(openssl rand -hex 24) docker compose up -d
```

Server is now live at `http://localhost:8097`. Save your admin secret.

### 2. Install the agent (on each node)

```bash
curl -fsSL http://YOUR_SERVER:8097/install.sh | sudo bash
sudo labwatch --register --server http://YOUR_SERVER:8097/api/v1 --admin-secret YOUR_SECRET
sudo systemctl enable --now labwatch
```

That's it. The agent auto-detects Docker, local services (SSH, HTTP, databases, Proxmox), and GPU — no manual config needed. Metrics start flowing immediately.

### Multi-node rollout

The agent can scan your LAN and show install commands for every SSH-capable host:

```bash
labwatch --discover
```

Output:
```
Found 5 SSH-capable hosts on the local network:

  192.168.1.100  (hypervisor.local)
  192.168.1.101  (docker-host.local)
  192.168.1.102  (nas.local)
  ...

Install labwatch on each host:
  ssh root@<IP> 'curl -fsSL http://YOUR_SERVER/install.sh | bash && labwatch --register ...'
```

### Server (manual, without Docker)

```bash
cd server
pip install -r requirements.txt
ADMIN_SECRET=your-secret uvicorn app:app --host 0.0.0.0 --port 8097
```

### Build agent from source

```bash
cd agent
go build -o labwatch -ldflags="-s -w" ./cmd/labwatch/
```

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  labwatch   │────>│   labwatch  │────>│   SQLite    │
│   agent     │     │   server    │     │   + alerts  │
│  (Go, 8MB)  │     │  (FastAPI)  │     │   + digest  │
└─────────────┘     └─────────────┘     └─────────────┘
  on each node        central host        persistent
```

**Agent**: single static Go binary (~8MB). No runtime dependencies. Sends metrics over HTTP every 60 seconds. Auto-detects Docker socket, local services (12 common ports), and NVIDIA GPUs during registration. Writes its own config — no YAML editing required.

**Server**: Python FastAPI with Jinja2 templates. SQLite in WAL mode. Runs rule-based analysis on every ingest cycle. Serves the dashboard, API, agent binaries, and install script from a single process.

## Dashboard

The dashboard shows your entire fleet at a glance:

- **Fleet summary** — total nodes, online count, active alerts, critical alerts, container count
- **Uptime widget** — 24-hour uptime timeline per node (green = up, red = down, gray = no data)
- **Alert feed widget** — chronological alert history with severity indicators
- **Node cards** — CPU/memory/disk bars with inline SVG sparklines showing 1-hour trends
- **Pin nodes** — star your important nodes to keep them at the top
- **Drag to reorder** — rearrange cards by dragging (touch supported with long-press)
- **Natural language query bar** — type questions directly in the UI

Layout preferences (pins, card order) persist in localStorage — no account needed.

## Demo mode

Visit `/demo` to see the dashboard with synthetic data. All features work: drag nodes around, pin them, ask queries, explore widgets. No account or agents required.

## User accounts

Users can sign up at `/signup` to get their own dashboard:

- Add nodes with a personal agent token
- Pin and reorder nodes
- Set custom alert thresholds per node
- Configure notification preferences
- Separate view from the admin dashboard

## Intelligence digests

labwatch generates narrative health reports:

```
media-server had a quiet last 24 hours. Running well below capacity.
CPU usage averaged just 2% — significant headroom for additional workloads.

Health Grade: A

CPU: 2.35% avg, peaked at 14.21%, currently 1.24%
Memory: 35.9% avg, range 34.75%-37.56%, currently 35.15%
Disk: 65.92% avg, currently 65.92%
Alerts: Clean — zero alerts this period
```

Fleet digest:
```
5 nodes monitored. 4 healthy, 1 fair, 0 need attention.

Node Grades: hypervisor A, docker-host A, media-server A, backup-nas B+, dev-server B-

Concerns:
- backup-nas: Sustained high load (12.4) — I/O pressure
- dev-server: Disk at 82% — approaching threshold
```

## Natural language queries

Ask questions in plain English from the dashboard or via API:

```bash
curl -X POST http://localhost:8097/api/v1/query \
  -H "X-Admin-Secret: your-secret" \
  -H "Content-Type: application/json" \
  -d '{"question": "Why is my NAS slow?"}'
```

| Type | Examples |
|------|----------|
| Fleet overview | "How's my lab?", "Give me a summary" |
| Status check | "Is plex running?", "Status of pve-storage" |
| Diagnostics | "Why is my server slow?", "What's causing high load?" |
| Capacity | "Am I running out of disk space?" |
| Comparative | "Which server uses the most CPU?" |
| Time range | "What happened last night?", "Any issues in the last 6 hours?" |

No LLM required — the engine uses pattern matching and template responses powered by your own metrics.

## Notifications

Push alerts to external services. Supported channels: **webhook** (Slack, Discord, custom) and **ntfy**.

```bash
curl -X POST http://localhost:8097/api/v1/admin/notifications \
  -H "X-Admin-Secret: your-secret" \
  -H "Content-Type: application/json" \
  -d '{"name": "phone", "channel_type": "ntfy", "config": {"server": "https://ntfy.sh", "topic": "my-homelab"}, "min_severity": "critical"}'
```

Notifications fire on **new** alerts only — deduplication prevents spam.

## Alert rules

| Alert | Severity | Condition | Auto-resolves |
|-------|----------|-----------|---------------|
| cpu_high | warning | CPU > 90% | Yes |
| memory_high | warning | Memory > 85% | Yes |
| memory_critical | critical | Memory > 95% | Yes |
| disk_high | warning | Disk > 80% | Yes |
| disk_critical | critical | Disk > 90% | Yes |
| load_high | warning | Load > 2x CPU count | Yes |
| container_restarts | warning | Restarts > 3 | Yes |
| service_failed | critical | Health check fails | Yes |

All alerts deduplicate automatically. When a condition clears, the alert resolves on the next cycle.

## API

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | — | Landing page |
| `/demo` | GET | — | Demo dashboard |
| `/health` | GET | — | Health check |
| `/install.sh` | GET | — | Agent install script |
| `/download/{binary}` | GET | — | Agent binary download |
| `/signup` | GET/POST | — | User registration |
| `/login` | GET/POST | — | User login |
| `/my/dashboard` | GET | User | User's dashboard |
| `/my/lab/{id}` | GET | User | User's node detail |
| `/dashboard` | GET | Admin | Admin fleet dashboard |
| `/dashboard/lab/{id}` | GET | Admin | Admin node detail |
| `/api/v1/register` | POST | Admin | Register agent |
| `/api/v1/ingest` | POST | Bearer | Submit metrics |
| `/api/v1/query` | POST | Admin | Natural language query |
| `/api/v1/widgets/uptime` | GET | Admin | Uptime timeline data |
| `/api/v1/widgets/alerts` | GET | Admin | Alert feed data |
| `/api/v1/widgets/sparkline/{id}/{metric}` | GET | Admin | Sparkline data |
| `/api/v1/admin/digest/{id}` | GET/POST | Admin | Node intelligence digest |
| `/api/v1/admin/digest` | POST | Admin | Fleet digest |
| `/api/v1/admin/notifications` | GET/POST | Admin | Notification channels |
| `/api/v1/my/pin/{id}` | POST/DELETE | User | Pin/unpin nodes |
| `/api/v1/my/thresholds/{id}` | GET/PUT/DELETE | User | Custom alert thresholds |

**Admin auth**: `X-Admin-Secret` header | **Bearer auth**: `Authorization: Bearer <token>` (from registration) | **User auth**: session cookie

## Tech stack

- **Agent**: Go, statically linked, ~8MB binary
- **Server**: Python 3.10+, FastAPI, SQLite (WAL mode), Jinja2
- **Dashboard**: vanilla HTML/CSS/JS, Chart.js for history charts, inline SVG sparklines
- **Design**: dark theme, amber accent, fully responsive

## Self-hosting

labwatch is designed to run entirely on your own hardware. No cloud dependencies, no telemetry, no external API calls. Your data stays on your network.

The server runs comfortably on a Raspberry Pi or any small VM. The agent uses <64MB RAM per node.

## License

- **Server** (Python/FastAPI): [AGPL-3.0](LICENSE)
- **Agent** (Go binary): [MIT](agent/LICENSE)

The agent is MIT-licensed so you can embed it anywhere without restrictions. The server is AGPL — if you modify and host it, share your changes.
