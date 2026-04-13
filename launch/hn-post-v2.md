# HN Post v2 — Post Cold-Eye Review

## Title

Show HN: Labwatch — "Why is my NAS slow?" answered from your metrics, no LLM

## Body

I run a 5-node Proxmox cluster (34 containers) at home. I wanted to type "what needs attention?" and get an answer from my own metrics — without shipping data to an API or configuring dashboards.

labwatch is a Go agent (8MB, auto-detects Docker and GPUs) that sends metrics to a FastAPI+SQLite server. The server runs rule-based analysis and answers natural-language questions using pattern matching against your data — about 20 query types including diagnostics, comparisons, and capacity checks. No LLM, no cloud dependency, no telemetry. When it doesn't understand a question, it says so instead of hallucinating.

Prometheus + Grafana is the right answer for production monitoring. This is for the rest of us who want to check on our homelab from a phone and get a plain-English answer. (If you do use Grafana, labwatch exposes a /metrics endpoint in Prometheus format — best of both worlds.)

The dashboard is server-rendered HTML with vanilla JS — no React, no webpack, no node_modules. The whole stack runs on a Raspberry Pi. The agent uses ~45MB RAM per node.

Demo (synthetic data, all features work): https://labwatch.dev/demo
Self-host: https://labwatch.dev/self-hosted
Source (MIT agent, AGPL server): https://github.com/labwatch-dev/labwatch

## Founder's Comment (post within 5 minutes)

A few things that aren't in the post:

**How the NLQ works:** It's ~3,600 lines of pattern matching and response templates with 20+ handler functions — status checks, diagnostics, fleet overviews, comparisons, capacity, container health, time-range queries, and more. Each handler pulls fresh metrics from SQLite and renders a template response. There's also typo normalization and multilingual input support (DE/FR/ES/UK). It's not magic — it's deterministic analysis that runs on your data with zero external calls. The fallback handler tells you what it can answer instead of guessing.

**Why not just use X:** Beszel is great for lightweight multi-host monitoring. Netdata is powerful but heavier. labwatch sits in between — fleet-wide visibility with natural language on top. Here's an honest feature comparison: https://labwatch.dev/#compare

**Architecture:** The agent auto-detects Docker (via socket) and NVIDIA GPUs. You can add HTTP/TCP service checks via the config file. Metrics flow every 60 seconds over HTTP. The server stores in SQLite WAL mode and runs rule-based alert analysis on every ingest cycle. Alerts auto-deduplicate and auto-resolve.

**Grafana integration:** If you already run Prometheus + Grafana, labwatch has a `/metrics` endpoint that exports all node data in Prometheus exposition format. You get labwatch's NLQ and alerts AND your existing Grafana dashboards.

**What this is NOT:** No log aggregation, no tracing, no custom dashboards, no PromQL. It's purpose-built for homelabs with 3-20 nodes.

I've been running this on my own cluster for months and just open-sourced it. Happy to answer any questions about the architecture, NLQ engine, or anything else.

---

## Changes from v1

Based on cold-eye review by 3 personas (homelab enthusiast, senior SWE, DevOps/SRE):

1. Removed "Prometheus is overkill" cliche → replaced with "Prometheus is the right answer for production. This is for the rest of us"
2. Made NLQ mechanism explicit: "pattern matching, ~20 query types, says so when it doesn't understand"
3. Added concrete numbers: 5 nodes, 34 containers, ~45MB RAM, 8MB binary
4. Specified what auto-detects means: Docker, GPUs (services configured in YAML)
5. Added "no React, no webpack, no node_modules" — HN loves this
6. Added licensing inline: "MIT agent, AGPL server"
7. Labeled demo link: "(synthetic data, all features work)"
8. Prepared founder's comment addressing: NLQ mechanism, competitor comparison, architecture, scope limitations
9. Frames open-sourcing honestly: "running on my own cluster for months, just open-sourced"
