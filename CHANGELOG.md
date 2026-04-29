# Changelog

All notable changes to this project will be documented in this file.

## [0.2.5] — 2026-04-29

### Added
- \`--register\` flag auto-writes config file with token and lab ID (no manual editing)
- \`--server\` and \`--secret\` CLI flags for zero-config registration
- Helpful error messages when token/server/secret are missing
- Agent retry with exponential backoff and jitter (3 retries, 2s/4s/8s)

### Changed
- Registration flow is now a single command: \`labwatch --register --server URL --secret SECRET\`
- Admin secret is not persisted in config file after registration
- Agent version bumped to 0.2.5

## [0.2.4] — 2026-04-29

### Added
- ZFS pool health monitoring (capacity, fragmentation, scrub status, error counts)
- S.M.A.R.T. disk health monitoring (temperature, reallocated sectors, power-on hours)
- ZFS natural language query handler ("How are my ZFS pools?", "ZFS pool status")
- ZFS demo chip on dashboard for interactive demo
- ZFS row in landing page comparison table
- ZFS carousel slide on landing page
- ZFS and S.M.A.R.T. collector types documented in API docs
- Pre-built agent binary for linux/armv7

### Fixed
- Signup API returned hardcoded `BASE_URL` (broken `labwatch.dev`) in install commands — now derives from request Host header
- Add-node API had the same `BASE_URL` issue
- Stripe checkout success/cancel URLs used hardcoded `BASE_URL` — now request-derived
- NLQ handler routing: ZFS queries incorrectly matched fleet_overview pattern (reordered handlers)
- Privacy policy and about page now accurately disclose self-hosted Umami analytics

## [0.2.3] — 2026-04-28

### Added
- Pre-built agent binaries for linux/amd64, linux/arm64, and linux/armv7
- `/download/{binary}.sha256` endpoint computes and serves checksums on the fly
- `scripts/build-agent.sh` for cross-compiling agent binaries

### Fixed
- SHA256 checksum route returned 404 due to route ordering (existence check ran before `.sha256` handler)
- Install script now correctly injects `BASE_URL` from server hostname

## [0.1.0] — 2026-04-12

### Added
- Initial public release
- Go agent for linux/amd64 and linux/arm64 (~8 MB static binary)
- FastAPI server with SQLite backend (WAL mode)
- Real-time fleet dashboard with sparklines and uptime timeline
- Docker container monitoring (health, restarts, resource usage)
- NVIDIA GPU monitoring via nvidia-smi
- Natural language query engine (regex-based, no LLM required)
- Intelligence digests with letter grades (A through C)
- Smart alerts with deduplication and auto-resolution
- 8 notification channels: webhook, ntfy, Discord, Slack, Telegram, Gotify, Pushover, Apprise
- Drag-and-drop card reordering (mouse and touch)
- Demo mode at `/demo` with synthetic data
- Multi-user accounts with personal dashboards
- Prometheus `/metrics` export endpoint
- Internationalization: English, German, French, Spanish, Ukrainian
- curl|bash installer with checksum verification
- Self-hosting guide and API documentation
