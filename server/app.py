"""Homelab Intelligence (labwatch) — FastAPI server.

Receives metrics from lightweight Go agents on customer homelabs,
stores them in SQLite, provides REST endpoints and a simple dashboard.
"""

import asyncio
import collections
import csv
import io
import hmac
import logging
import re as _re
import sys
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
try:
    from starlette.middleware.gzip import GZipMiddleware as GzipMiddleware
except ImportError:
    from starlette.middleware.gzip import GzipMiddleware

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(name)s: %(message)s")

import config
import database as db
import mailer
from analyzer import analyze_metrics
from i18n import detect_language, get_translations, SUPPORTED_LANGUAGES, LANGUAGE_NAMES
from models import MetricPayload, RegisterRequest, RegisterResponse, SignupRequest, LogIngestPayload

# ---------------------------------------------------------------------------
# In-memory rate limiter (login brute-force protection)
# ---------------------------------------------------------------------------

_login_attempts: dict[str, list[float]] = collections.defaultdict(list)
_login_attempts_last_gc: float = 0.0

def _check_login_rate(ip: str, max_attempts: int = 10, window: int = 300) -> bool:
    """Returns True if the IP is under the login rate limit (10 attempts per 5 min)."""
    global _login_attempts_last_gc
    now = time.monotonic()
    # Periodic full cleanup (every 10 min) to prevent unbounded growth
    if now - _login_attempts_last_gc > 600:
        stale = [k for k, v in _login_attempts.items() if not v or now - v[-1] > window]
        for k in stale:
            del _login_attempts[k]
        _login_attempts_last_gc = now
    attempts = _login_attempts.get(ip, [])
    # Prune old entries for this IP
    pruned = [t for t in attempts if now - t < window]
    if pruned:
        _login_attempts[ip] = pruned
    elif ip in _login_attempts:
        del _login_attempts[ip]
    return len(pruned) < max_attempts

def _record_login_attempt(ip: str):
    _login_attempts[ip].append(time.monotonic())


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="labwatch",
    description="Homelab Intelligence monitoring service",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(GzipMiddleware, minimum_size=1000)

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

# Starlette 1.0 changed TemplateResponse(name, ctx) → TemplateResponse(request, name, ctx).
import starlette as _starlette_mod
_STARLETTE_NEW_TPL = int(_starlette_mod.__version__.split(".")[0]) >= 1

def _render(name: str, ctx: dict, **kwargs):
    if _STARLETTE_NEW_TPL:
        return templates.TemplateResponse(ctx["request"], name, ctx, **kwargs)
    return templates.TemplateResponse(name, ctx, **kwargs)


_MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MB — generous for metric ingest, blocks abuse


@app.middleware("http")
async def body_size_limit(request: Request, call_next):
    """Reject requests with Content-Length exceeding the limit (DoS protection)."""
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > _MAX_BODY_BYTES:
        return JSONResponse(
            content={"detail": "Request body too large"},
            status_code=413,
        )
    return await call_next(request)


@app.middleware("http")
async def csrf_origin_check(request: Request, call_next):
    """Block cross-origin form POSTs to state-changing endpoints (CSRF protection).

    Checks Origin/Referer header on POST requests to browser-facing routes.
    API routes (Bearer/admin auth) are excluded — they're not vulnerable to CSRF.
    """
    if request.method in ("POST", "PUT", "DELETE"):
        path = request.url.path
        # Check all session-authenticated endpoints + browser forms
        # Skip API routes that use Bearer/admin auth (not CSRF-vulnerable)
        csrf_paths = {"/login", "/signup", "/set-password"}
        # Stripe webhook has its own signature verification — exempt from CSRF
        is_session_api = (
            path.startswith("/api/v1/my/")
            or (path.startswith("/api/v1/billing/") and path != "/api/v1/billing/webhook")
        )
        if path in csrf_paths or is_session_api:
            origin = request.headers.get("origin") or ""
            referer = request.headers.get("referer") or ""
            expected_origin = config.BASE_URL.rstrip("/")
            from urllib.parse import urlparse
            expected_host = urlparse(expected_origin).netloc
            origin_ok = (
                not origin  # Some browsers omit Origin on same-origin
                or urlparse(origin).netloc == expected_host
            )
            referer_ok = (
                not referer
                or urlparse(referer).netloc == expected_host
            )
            if not origin_ok and not referer_ok:
                return JSONResponse(
                    content={"detail": "Cross-origin request blocked"},
                    status_code=403,
                )
    return await call_next(request)


_STATIC_PAGES = frozenset({"/", "/docs", "/about", "/privacy", "/terms", "/support", "/self-hosted", "/compare", "/blog/why-we-built-labwatch"})

@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Generate per-request nonce for CSP
    request.state.csp_nonce = secrets.token_urlsafe(24)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    nonce = request.state.csp_nonce
    response.headers["Content-Security-Policy"] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; style-src 'self' 'nonce-{nonce}'; img-src 'self' data: https://img.shields.io; font-src 'self'"
    # Cache headers: static marketing pages cacheable, dashboard private
    path = request.url.path
    if path in _STATIC_PAGES:
        response.headers["Cache-Control"] = "public, max-age=300"
    elif path.startswith("/my/") or path.startswith("/dashboard"):
        response.headers["Cache-Control"] = "private, max-age=30"
    return response


def _md_bold(text: str) -> str:
    """Convert markdown **bold** and ### headings to HTML.

    HTML-escapes the input first to prevent XSS from metric data
    (e.g. crafted hostnames), then applies safe markdown formatting.
    """
    import re
    from markupsafe import escape
    text = str(escape(text))
    text = re.sub(r'^### (.+)$', r'<strong>\1</strong>', text, flags=re.MULTILINE)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'^- ', r'&bull; ', text, flags=re.MULTILINE)
    return text


templates.env.filters["md_bold"] = _md_bold

_purge_task = None


def _run_tier_purge(logger: logging.Logger) -> None:
    """Run one round of tier-aware metric purging + global alert purge."""
    purged = db.purge_metrics_per_tier(config.TIER_LIMITS, config.DEFAULT_PLAN)
    if purged:
        logger.info(f"Periodic purge: removed {purged} metrics (tier-aware retention)")
    alert_purged = db.purge_old_alerts(hours=720)
    if alert_purged:
        logger.info(f"Periodic purge: removed {alert_purged} alerts older than 30 days")
    log_purged = db.purge_logs_per_tier(config.LOG_TIER_LIMITS, config.DEFAULT_PLAN)
    if log_purged:
        logger.info(f"Periodic purge: removed {log_purged} log entries (tier-aware retention)")


async def _periodic_purge():
    """Run the tier-aware purge every 6 hours."""
    logger = logging.getLogger("labwatch")
    while True:
        await asyncio.sleep(6 * 3600)
        try:
            _run_tier_purge(logger)
        except Exception:
            logger.exception("Periodic purge failed — will retry next cycle")


_OFFLINE_THRESHOLD_MINUTES = 5


async def _check_stale_nodes():
    """Periodically check for nodes that stopped reporting and create/resolve alerts."""
    logger = logging.getLogger("labwatch")
    while True:
        await asyncio.sleep(120)  # every 2 minutes
        try:
            labs = db.list_labs()
            for lab in labs:
                online = _lab_is_online(lab.get("last_seen"), _OFFLINE_THRESHOLD_MINUTES)
                if not online:
                    # Create node_offline alert if not already active
                    existing = db.get_active_alerts(lab["id"])
                    already_offline = any(a.get("alert_type") == "node_offline" for a in existing)
                    if not already_offline:
                        from notifications import send_alert_notification
                        msg = f"No heartbeat from {lab.get('hostname', lab['id'])} for >{_OFFLINE_THRESHOLD_MINUTES} minutes"
                        alert_id, is_new = db.store_alert(
                            lab_id=lab["id"],
                            alert_type="node_offline",
                            severity="critical",
                            message=msg,
                            data={"last_seen": lab.get("last_seen")},
                        )
                        if is_new:
                            try:
                                # Run sync HTTP dispatch in a thread to avoid blocking the event loop
                                await asyncio.to_thread(
                                    send_alert_notification,
                                    {"type": "node_offline", "severity": "critical", "message": msg},
                                    lab,
                                )
                            except Exception:
                                logger.exception("Failed to send node_offline notification")
                else:
                    # Resolve node_offline alert if node is back
                    db.resolve_alerts(lab["id"], ["node_offline"])
        except Exception:
            logger.exception("Stale node check failed — will retry next cycle")


@app.on_event("startup")
def startup():
    global _purge_task
    db.init_db()
    _run_tier_purge(logging.getLogger("labwatch"))
    loop = asyncio.get_event_loop()
    _purge_task = loop.create_task(_periodic_purge())
    loop.create_task(_check_stale_nodes())


def _tier_retention_hours(email: Optional[str]) -> int:
    """Retention window (hours) for a given user email, or default plan if unknown."""
    plan = config.DEFAULT_PLAN
    if email:
        plan = db.get_plan_for_email(email, default=config.DEFAULT_PLAN)
    limits = config.TIER_LIMITS.get(plan) or config.TIER_LIMITS[config.DEFAULT_PLAN]
    return int(limits.get("retention_hours") or config.RETENTION_HOURS)


def _tier_node_cap(email: Optional[str]) -> Optional[int]:
    """Node cap for a given user email (None = unlimited)."""
    plan = config.DEFAULT_PLAN
    if email:
        plan = db.get_plan_for_email(email, default=config.DEFAULT_PLAN)
    limits = config.TIER_LIMITS.get(plan) or config.TIER_LIMITS[config.DEFAULT_PLAN]
    return limits.get("node_cap")


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.exception_handler(404)
def not_found_handler(request: Request, exc):
    """Custom 404 page."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return HTMLResponse(
            content=f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>404 — labwatch</title>
<style>
body {{ background: #0a0a0f; color: #e0e0e8; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
.error-page {{ text-align: center; max-width: 480px; padding: 40px 24px; }}
.error-code {{ font-size: 72px; font-weight: 800; color: #f0a030; font-family: 'SF Mono', monospace; margin-bottom: 8px; }}
.error-msg {{ font-size: 18px; color: #8888a0; margin-bottom: 32px; }}
.error-link {{ display: inline-block; padding: 10px 24px; background: #f0a030; color: #0a0a0f; border-radius: 8px; font-weight: 600; text-decoration: none; font-size: 14px; }}
.error-link:hover {{ background: #fbb040; }}
</style></head>
<body><div class="error-page">
<div class="error-code">404</div>
<div class="error-msg">This page doesn't exist.</div>
<a href="/" class="error-link">Back to labwatch</a>
</div></body></html>""",
            status_code=404,
        )
    return JSONResponse(content={"detail": "Not Found"}, status_code=404)


@app.exception_handler(500)
def server_error_handler(request: Request, exc):
    """Custom 500 page."""
    logging.getLogger("labwatch").error(f"Internal error on {request.url.path}: {exc}")
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return HTMLResponse(
            content=f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>500 — labwatch</title>
<style>
body {{ background: #0a0a0f; color: #e0e0e8; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
.error-page {{ text-align: center; max-width: 480px; padding: 40px 24px; }}
.error-code {{ font-size: 72px; font-weight: 800; color: #e04040; font-family: 'SF Mono', monospace; margin-bottom: 8px; }}
.error-msg {{ font-size: 18px; color: #8888a0; margin-bottom: 32px; }}
.error-link {{ display: inline-block; padding: 10px 24px; background: #f0a030; color: #0a0a0f; border-radius: 8px; font-weight: 600; text-decoration: none; font-size: 14px; }}
.error-link:hover {{ background: #fbb040; }}
</style></head>
<body><div class="error-page">
<div class="error-code">500</div>
<div class="error-msg">Something went wrong. We're on it.</div>
<a href="/" class="error-link">Back to labwatch</a>
</div></body></html>""",
            status_code=500,
        )
    return JSONResponse(content={"detail": "Internal Server Error"}, status_code=500)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _get_bearer_token(authorization: Optional[str] = Header(None)) -> str:
    """Extract Bearer token from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer token")
    return authorization[7:]


def _require_agent_auth(authorization: Optional[str] = Header(None)) -> dict:
    """Authenticate an agent by Bearer token. Returns the lab dict."""
    token = _get_bearer_token(authorization)
    lab = db.get_lab_by_token(token)
    if not lab:
        raise HTTPException(status_code=401, detail="Invalid token")
    return lab


def _require_admin(x_admin_secret: Optional[str] = Header(None)) -> str:
    """Validate admin secret header."""
    if not x_admin_secret or not hmac.compare_digest(x_admin_secret, config.ADMIN_SECRET):
        raise HTTPException(status_code=403, detail="Invalid admin secret")
    return x_admin_secret


# ---------------------------------------------------------------------------
# Session auth (cookie-based, for browser users)
# ---------------------------------------------------------------------------

_session_signer = URLSafeTimedSerializer(config.SESSION_SECRET)
_SESSION_COOKIE = "labwatch_session"
_SESSION_MAX_AGE = 30 * 24 * 3600  # 30 days


def _get_session_email(request: Request) -> Optional[str]:
    """Read and validate session cookie. Returns email or None."""
    cookie = request.cookies.get(_SESSION_COOKIE)
    if not cookie:
        return None
    try:
        email = _session_signer.loads(cookie, max_age=_SESSION_MAX_AGE)
        return email
    except (BadSignature, SignatureExpired):
        return None


def _set_session_cookie(response, email: str):
    """Set signed session cookie on response."""
    token = _session_signer.dumps(email)
    response.set_cookie(
        _SESSION_COOKIE, token,
        max_age=_SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=config.BASE_URL.startswith("https"),
    )
    return response


# ---------------------------------------------------------------------------
# Template context helper
# ---------------------------------------------------------------------------

def _request_base_url(request: Request) -> str:
    """Derive base URL from request Host header so install commands work
    regardless of which domain the visitor used."""
    import re
    host = request.headers.get("host", "")
    if host and re.fullmatch(r'[A-Za-z0-9._:-]+', host):
        scheme = "https" if request.headers.get("x-forwarded-proto") == "https" or request.url.scheme == "https" else "http"
        return f"{scheme}://{host}"
    return config.BASE_URL


def _tpl_context(request: Request, **kwargs) -> dict:
    """Build template context with i18n, session, and custom kwargs."""
    lang = detect_language(request)
    t = get_translations(lang)
    ctx = {
        "request": request,
        "t": t,
        "lang": lang,
        "languages": SUPPORTED_LANGUAGES,
        "language_names": LANGUAGE_NAMES,
        "user_email": _get_session_email(request),
        "base_url": _request_base_url(request),
        "secret": "",
        "csp_nonce": getattr(request.state, "csp_nonce", ""),
    }
    ctx.update(kwargs)
    return ctx


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _lab_is_online(last_seen: Optional[str], threshold_minutes: int = 5) -> bool:
    """Check if a lab has reported within the threshold."""
    if not last_seen:
        return False
    try:
        ts = datetime.fromisoformat(last_seen)
        return (datetime.now(timezone.utc) - ts) < timedelta(minutes=threshold_minutes)
    except (ValueError, TypeError):
        return False


def _format_load_avg(load_avg) -> str:
    """Format load average dict/list into a readable string."""
    if isinstance(load_avg, dict):
        l1 = load_avg.get("load1", 0) or 0
        l5 = load_avg.get("load5", 0) or 0
        l15 = load_avg.get("load15", 0) or 0
        return f"{l1:.2f} / {l5:.2f} / {l15:.2f}"
    if isinstance(load_avg, (list, tuple)) and load_avg:
        return " / ".join(f"{v:.2f}" for v in load_avg[:3])
    return "--"


_SECRET_CONFIG_KEYS = {"token", "bot_token", "api_token", "user_key", "webhook_url", "url", "secret"}

def _redact_channel_config(channel: dict) -> dict:
    """Redact secrets from a notification channel config before returning to client."""
    ch = dict(channel)
    if "config" in ch and isinstance(ch["config"], (str, dict)):
        import json as _json
        cfg = ch["config"]
        if isinstance(cfg, str):
            try:
                cfg = _json.loads(cfg)
            except (ValueError, TypeError):
                cfg = {}
        redacted = {}
        for k, v in cfg.items():
            if k in _SECRET_CONFIG_KEYS and isinstance(v, str) and len(v) > 4:
                redacted[k] = v[:4] + "..." + v[-2:]
            else:
                redacted[k] = v
        ch["config"] = redacted
    return ch


def _extract_system_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    """Pull top-level numbers from the latest system metrics for display."""
    system_entry = metrics.get("system", {})
    data = system_entry.get("data", {}) if isinstance(system_entry, dict) else {}
    # Extract from Go agent's nested structure
    cpu = data.get("cpu", {})
    mem = data.get("memory", {})
    disks = data.get("disk", data.get("disks", []))
    disk_pct = disks[0].get("used_percent", 0) if isinstance(disks, list) and disks else 0
    # Sum network bytes across all interfaces
    network = data.get("network", [])
    total_rx = sum(n.get("bytes_recv", 0) for n in network)
    total_tx = sum(n.get("bytes_sent", 0) for n in network)
    return {
        "cpu_percent": cpu.get("total_percent", 0) or 0,
        "memory_percent": mem.get("used_percent", 0) or 0,
        "disk_percent": disk_pct or 0,
        "uptime_seconds": data.get("uptime_seconds", 0) or 0,
        "load_average": _format_load_avg(data.get("load_average", {})),
        "cpu_count": cpu.get("count", 0) or 0,
        "memory_total_bytes": mem.get("total_bytes", 0),
        "memory_total_gb": round((mem.get("total_bytes", 0) or 0) / (1024**3), 1),
        "disk_total_gb": round((disks[0].get("total_bytes", 0) or 0) / (1024**3), 1) if isinstance(disks, list) and disks else 0,
        "network": network,
        "net_rx_bytes": total_rx,
        "net_tx_bytes": total_tx,
        "temperatures": data.get("temperatures", []),
        "processes": data.get("processes", []),
    }


def _enrich_network_rate(system_summary: dict, lab_id: str) -> None:
    """Compute network Mbps by comparing the two most recent system samples."""
    samples = db.get_recent_system_samples(lab_id, count=2)
    if len(samples) < 2:
        return
    cur, prev = samples[0], samples[1]
    try:
        from datetime import datetime as _dt
        t_cur = _dt.fromisoformat(cur["timestamp"])
        t_prev = _dt.fromisoformat(prev["timestamp"])
        delta_s = (t_cur - t_prev).total_seconds()
        if delta_s <= 0:
            return
        cur_net = cur["data"].get("network", [])
        prev_net = prev["data"].get("network", [])
        prev_map = {n["interface"]: n for n in prev_net}
        rx_delta = tx_delta = 0
        for iface in cur_net:
            if iface.get("interface") == "lo":
                continue
            p = prev_map.get(iface["interface"], {})
            rx_delta += max(0, iface.get("bytes_recv", 0) - p.get("bytes_recv", 0))
            tx_delta += max(0, iface.get("bytes_sent", 0) - p.get("bytes_sent", 0))
        system_summary["net_rx_mbps"] = min(round(rx_delta * 8 / delta_s / 1_000_000, 2), 1000)
        system_summary["net_tx_mbps"] = min(round(tx_delta * 8 / delta_s / 1_000_000, 2), 1000)
    except Exception:
        logging.getLogger("labwatch").debug("Network rate enrichment failed", exc_info=True)


def _extract_gpu_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    """Pull GPU metrics from latest gpu collector data."""
    gpu_entry = metrics.get("gpu", {})
    data = gpu_entry.get("data", {}) if isinstance(gpu_entry, dict) else {}
    devices = data.get("devices", [])
    return {
        "gpu_count": data.get("count", len(devices) if isinstance(devices, list) else 0),
        "gpus": devices if isinstance(devices, list) else [],
    }


def _extract_docker_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    """Pull container summary from latest docker metrics."""
    docker_entry = metrics.get("docker", {})
    data = docker_entry.get("data", {}) if isinstance(docker_entry, dict) else {}
    containers = data.get("containers", [])
    return {
        "container_count": len(containers) if isinstance(containers, list) else 0,
        "containers": containers,
    }


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return _render("landing.html", _tpl_context(request))


@app.get("/docs", response_class=HTMLResponse)
def api_docs(request: Request):
    return _render("docs.html", _tpl_context(request, active_page="docs"))


@app.get("/about", response_class=HTMLResponse)
def about_page(request: Request):
    return _render("about.html", _tpl_context(request, active_page="about"))


@app.get("/support", response_class=HTMLResponse)
def support_page(request: Request):
    return _render("support.html", _tpl_context(request, active_page="support"))


@app.get("/self-hosted", response_class=HTMLResponse)
def self_hosted_page(request: Request):
    return _render("self_hosted.html", _tpl_context(request, active_page="self_hosted"))


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page(request: Request):
    return _render("privacy.html", _tpl_context(request, active_page="privacy"))


@app.get("/terms", response_class=HTMLResponse)
def terms_page(request: Request):
    return _render("terms.html", _tpl_context(request, active_page="terms"))


@app.get("/blog/why-we-built-labwatch", response_class=HTMLResponse)
def blog_launch(request: Request):
    return _render("blog_launch.html", _tpl_context(request))


@app.get("/ember", response_class=HTMLResponse)
def ember_page(request: Request, via: str = "direct"):
    """Easter egg discovery page. Sets ember_unlocked in response."""
    conn = db._connect()
    try:
        row = conn.execute("SELECT email, found_via, claimed_at FROM ember_claims ORDER BY id LIMIT 1").fetchone()
    finally:
        conn.close()
    winner = None
    if row:
        email = row[0]
        at_idx = email.index("@")
        obscured = email[0] + "*" * (at_idx - 1) + email[at_idx:]
        winner = {"email_obscured": obscured, "found_via": row[1], "claimed_at": row[2][:10]}
    found_via = via if via in ("install", "nlq", "direct") else "direct"
    ctx = _tpl_context(request, winner=winner, found_via=found_via)
    response = _render("ember.html", ctx)
    response.set_cookie("ember_unlocked", "1", max_age=86400 * 365 * 3, httponly=False, samesite="lax")
    return response


@app.post("/api/v1/ember/claim")
async def ember_claim(request: Request):
    """Claim the ember easter egg prize. One winner total."""
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    found_via = body.get("found_via", "direct")
    if not email or "@" not in email:
        return JSONResponse({"detail": "valid email required"}, status_code=400)
    if found_via not in ("install", "nlq", "direct"):
        found_via = "direct"
    conn = db._connect()
    try:
        existing = conn.execute("SELECT id FROM ember_claims LIMIT 1").fetchone()
        if existing:
            return JSONResponse({"already_claimed": True}, status_code=409)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO ember_claims (email, found_via, claimed_at) VALUES (?, ?, ?)",
            (email, found_via, now),
        )
        conn.commit()
    finally:
        conn.close()
    return JSONResponse({"success": True, "email": email})


@app.get("/pricing", response_class=HTMLResponse)
def pricing_page(request: Request):
    # Serve the landing page and auto-scroll to the pricing section so that
    # direct links from Reddit / HN land on pricing without a 302 redirect.
    ctx = _tpl_context(request, scroll_to="pricing")
    return _render("landing.html", ctx)


@app.get("/compare")
def compare_redirect():
    # Compare lives as a section on the landing page.
    return RedirectResponse("/#compare", status_code=302)


@app.get("/health")
@app.get("/api/v1/health")
def health():
    try:
        conn = db._connect()
        try:
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()
    except Exception:
        return JSONResponse(
            content={"status": "unhealthy", "service": "labwatch", "detail": "database unreachable"},
            status_code=503,
        )
    return {"status": "ok", "service": "labwatch", "version": "1.0.0", "schema_version": db.get_schema_version()}


@app.get("/metrics")
@app.get("/api/v1/metrics")
def prometheus_metrics(
    request: Request,
    x_admin_secret: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    """Export all lab metrics in Prometheus exposition format.

    Accepts admin secret via X-Admin-Secret header or standard
    Authorization: Bearer <secret> (for Prometheus scraper compatibility).
    """
    secret = x_admin_secret
    if not secret and authorization and authorization.startswith("Bearer "):
        secret = authorization[7:]
    if not secret or not hmac.compare_digest(secret, config.ADMIN_SECRET):
        raise HTTPException(status_code=403, detail="Forbidden")

    labs = db.list_labs()
    lines = [
        "# HELP labwatch_cpu_percent Current CPU usage percentage per node.",
        "# TYPE labwatch_cpu_percent gauge",
        "# HELP labwatch_memory_percent Current memory usage percentage per node.",
        "# TYPE labwatch_memory_percent gauge",
        "# HELP labwatch_disk_percent Current disk usage percentage per node.",
        "# TYPE labwatch_disk_percent gauge",
        "# HELP labwatch_uptime_seconds Node uptime in seconds.",
        "# TYPE labwatch_uptime_seconds gauge",
        "# HELP labwatch_containers_total Total number of containers per node.",
        "# TYPE labwatch_containers_total gauge",
        "# HELP labwatch_containers_running Running containers per node.",
        "# TYPE labwatch_containers_running gauge",
        "# HELP labwatch_alerts_active Active alerts per node.",
        "# TYPE labwatch_alerts_active gauge",
        "# HELP labwatch_node_online Whether the node is online (1) or offline (0).",
        "# TYPE labwatch_node_online gauge",
        "# HELP labwatch_gpu_utilization_percent GPU utilization percentage.",
        "# TYPE labwatch_gpu_utilization_percent gauge",
        "# HELP labwatch_gpu_temperature_celsius GPU temperature in Celsius.",
        "# TYPE labwatch_gpu_temperature_celsius gauge",
        "# HELP labwatch_smart_healthy Whether the disk is healthy (1) or failing (0).",
        "# TYPE labwatch_smart_healthy gauge",
        "# HELP labwatch_smart_temperature_celsius Disk temperature in Celsius.",
        "# TYPE labwatch_smart_temperature_celsius gauge",
        "# HELP labwatch_zfs_pool_used_percent ZFS pool usage percentage.",
        "# TYPE labwatch_zfs_pool_used_percent gauge",
        "# HELP labwatch_zfs_pool_healthy Whether the ZFS pool is healthy (1) or degraded (0).",
        "# TYPE labwatch_zfs_pool_healthy gauge",
    ]

    for lab in labs:
        lab_id = lab["id"]
        hostname = lab.get("hostname", lab_id)
        _esc = lambda v: v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        labels = f'lab_id="{_esc(lab_id)}",hostname="{_esc(hostname)}"'

        metrics = db.get_latest_metrics(lab_id)
        summary = _extract_system_summary(metrics)

        online = 1 if lab.get("online") else 0
        lines.append(f"labwatch_node_online{{{labels}}} {online}")
        lines.append(f'labwatch_cpu_percent{{{labels}}} {summary.get("cpu_percent", 0)}')
        lines.append(f'labwatch_memory_percent{{{labels}}} {summary.get("memory_percent", 0)}')
        lines.append(f'labwatch_disk_percent{{{labels}}} {summary.get("disk_percent", 0)}')
        lines.append(f'labwatch_uptime_seconds{{{labels}}} {summary.get("uptime_seconds", 0)}')

        # Container stats from docker metrics
        docker_entry = metrics.get("docker", {})
        docker_data = docker_entry.get("data", {}) if isinstance(docker_entry, dict) else {}
        containers = docker_data.get("containers", [])
        total = len(containers)
        running = sum(1 for c in containers if c.get("state") == "running")
        lines.append(f"labwatch_containers_total{{{labels}}} {total}")
        lines.append(f"labwatch_containers_running{{{labels}}} {running}")

        # Active alerts
        alerts = db.get_active_alerts(lab_id)
        lines.append(f"labwatch_alerts_active{{{labels}}} {len(alerts)}")

        # GPU metrics
        gpu_entry = metrics.get("gpu", {})
        gpu_data = gpu_entry.get("data", {}) if isinstance(gpu_entry, dict) else {}
        for gpu in gpu_data.get("gpus", []):
            gpu_id = gpu.get("index", 0)
            gl = f'{labels},gpu="{gpu_id}"'
            if "utilization" in gpu:
                lines.append(f"labwatch_gpu_utilization_percent{{{gl}}} {gpu['utilization']}")
            if "temperature" in gpu:
                lines.append(f"labwatch_gpu_temperature_celsius{{{gl}}} {gpu['temperature']}")

        # S.M.A.R.T. disk health
        smart_entry = metrics.get("smart", {})
        smart_data = smart_entry.get("data", smart_entry) if isinstance(smart_entry, dict) else {}
        for disk in smart_data.get("devices", []):
            dev = disk.get("device", "unknown").replace('"', '')
            dl = f'{labels},device="{dev}"'
            lines.append(f"labwatch_smart_healthy{{{dl}}} {1 if disk.get('healthy', True) else 0}")
            if disk.get("temperature_c"):
                lines.append(f"labwatch_smart_temperature_celsius{{{dl}}} {disk['temperature_c']}")

        # ZFS pool health
        zfs_entry = metrics.get("zfs", {})
        zfs_data = zfs_entry.get("data", {}) if isinstance(zfs_entry, dict) else {}
        for pool in zfs_data.get("pools", []):
            pn = pool.get("name", "unknown").replace('"', '')
            pl = f'{labels},pool="{pn}"'
            lines.append(f"labwatch_zfs_pool_used_percent{{{pl}}} {pool.get('used_percent', 0):.1f}")
            healthy = 1 if pool.get("health", "").upper() == "ONLINE" else 0
            lines.append(f"labwatch_zfs_pool_healthy{{{pl}}} {healthy}")

    lines.append("")  # trailing newline
    return PlainTextResponse("\n".join(lines), media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/favicon.ico")
def favicon():
    svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><circle cx='16' cy='16' r='14' fill='#f0a030'/></svg>"
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots_txt():
    return (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /api/\n"
        "Disallow: /my/\n"
        "Disallow: /dashboard\n"
        "Disallow: /billing/\n"
        "Disallow: /login\n"
        "Disallow: /signup\n"
        "\n"
        f"Sitemap: {config.BASE_URL}/sitemap.xml\n"
    )


@app.get("/sitemap.xml", response_class=PlainTextResponse)
def sitemap_xml():
    urls = [
        "", "/demo", "/docs", "/about", "/support",
        "/self-hosted", "/privacy", "/terms",
    ]
    entries = "\n".join(
        f"  <url><loc>{config.BASE_URL}{u}</loc></url>" for u in urls
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{entries}\n"
        "</urlset>\n"
    )


@app.get("/install.sh", response_class=PlainTextResponse)
def install_script(request: Request):
    """Serve the install script with BASE_URL pre-configured."""
    # Check local copy first (Docker), then sibling agent dir (dev)
    script_path = Path(__file__).parent / "install.sh"
    if not script_path.exists():
        script_path = Path(__file__).parent.parent / "agent" / "install.sh"
    if not script_path.exists():
        raise HTTPException(status_code=404, detail="Install script not found")
    script = script_path.read_text()
    # Derive URL from the request so the install command works regardless
    # of which domain the visitor used (labwatch.dev vs duckdns fallback).
    import re
    host = request.headers.get("host", "")
    scheme = "https" if request.headers.get("x-forwarded-proto") == "https" or request.url.scheme == "https" else "http"
    if host and re.fullmatch(r'[A-Za-z0-9._:-]+', host):
        safe_url = f"{scheme}://{host}"
    else:
        safe_url = config.BASE_URL
        if not re.fullmatch(r'https?://[A-Za-z0-9._:/-]+', safe_url):
            safe_url = "https://labwatch.dev"
    script = script.replace(
        'BASE_URL="${LABWATCH_URL:-https://labwatch.dev}"',
        f'BASE_URL="${{LABWATCH_URL:-{safe_url}}}"',
    )
    return script


@app.get("/download/{filename}")
def download_binary(filename: str):
    """Serve agent binary downloads."""
    from fastapi.responses import FileResponse
    dist_dir = Path(__file__).parent / "dist"
    file_path = (dist_dir / filename).resolve()
    if not str(file_path).startswith(str(dist_dir.resolve()) + "/"):
        raise HTTPException(status_code=400, detail="Invalid filename")
    if filename.endswith(".sha256"):
        # Serve checksum for the corresponding binary
        bin_path = file_path.with_suffix("")  # strip .sha256
        if not bin_path.exists():
            raise HTTPException(status_code=404, detail="Binary not found")
        import hashlib
        sha = hashlib.sha256(bin_path.read_bytes()).hexdigest()
        return PlainTextResponse(sha)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Binary not found")
    return FileResponse(
        file_path,
        media_type="application/octet-stream",
        filename=filename,
    )


# ---------------------------------------------------------------------------
# Self-service signup
# ---------------------------------------------------------------------------

@app.post("/api/v1/signup")
def signup(body: SignupRequest, request: Request):
    """Self-service signup for free tier. No admin secret required."""
    import re

    # Require terms acceptance
    if not body.accept_terms:
        raise HTTPException(status_code=400, detail="You must accept the Terms of Service and Privacy Policy")

    # Normalize email to lowercase to prevent case-based duplicates
    body.email = body.email.strip().lower()

    # Validate email format
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", body.email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    # Rate limit by IP
    client_ip = request.client.host if request.client else "unknown"
    if not db.check_signup_rate(client_ip):
        raise HTTPException(status_code=429, detail="Too many signups. Try again later.")

    # Enforce node cap for the email's plan (defaults to free for new signups).
    cap = _tier_node_cap(body.email)
    if cap is not None and db.count_labs_for_email(body.email) >= cap:
        raise HTTPException(
            status_code=400,
            detail=f"Free plan allows {cap} nodes. Upgrade to Pro for unlimited.",
        )

    # Validate password if provided
    if body.password is not None:
        if len(body.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        if len(body.password) > 128:
            raise HTTPException(status_code=400, detail="Password must be at most 128 characters")

    # Sanitize hostname
    hostname = re.sub(r"[^a-zA-Z0-9._-]", "", body.hostname)[:64] or "my-server"

    lab_id, token = db.signup_lab(body.email, hostname, client_ip, body.password)

    base = _request_base_url(request)
    return {
        "lab_id": lab_id,
        "token": token,
        "install_command": f'curl -fsSL {base}/install.sh | sudo bash',
        "config_snippet": (
            f"api_endpoint: \"{base}/api/v1\"\n"
            f"token: \"{token}\"\n"
            f"lab_id: \"{lab_id}\"\n"
            f"interval: 60s\n"
            f"docker:\n"
            f"  enabled: true\n"
            f"  socket: /var/run/docker.sock"
        ),
        "next_steps": [
            f"Run: curl -fsSL {base}/install.sh | sudo bash",
            f"Save config to /etc/labwatch/config.yaml",
            "Run: sudo systemctl enable --now labwatch",
            f"View your dashboard at {base}/my/dashboard",
        ],
    }


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    """Self-service signup page."""
    return _render("signup.html", _tpl_context(request))


# ---------------------------------------------------------------------------
# User auth (login / logout / user dashboard)
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Login page for existing users."""
    email = _get_session_email(request)
    if email:
        return RedirectResponse("/my/dashboard", status_code=302)
    error = request.query_params.get("error")
    return _render("login.html", _tpl_context(request, error=error, active_page="login"))


@app.post("/login")
def login_submit(
    request: Request,
    token: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    method: str = Form("token"),
):
    """Authenticate user by token or email+password, set session cookie."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_login_rate(client_ip):
        return RedirectResponse("/login?error=Too+many+attempts.+Try+again+in+a+few+minutes.", status_code=302)
    _record_login_attempt(client_ip)

    if method == "email":
        # Email + password login
        email = email.strip().lower()
        if not email or not password:
            return RedirectResponse("/login?error=Please+enter+email+and+password&tab=email", status_code=302)
        if len(password) > 128:
            return RedirectResponse("/login?error=Invalid+email+or+password&tab=email", status_code=302)

        if not db.verify_login(email, password):
            return RedirectResponse("/login?error=Invalid+email+or+password&tab=email", status_code=302)

        response = RedirectResponse("/my/dashboard", status_code=302)
        _set_session_cookie(response, email)
        return response
    else:
        # Token login (original flow)
        token = token.strip()
        if not token:
            return RedirectResponse("/login?error=Please+enter+your+token&tab=token", status_code=302)

        lab = db.get_lab_by_token(token)
        if not lab:
            return RedirectResponse("/login?error=Invalid+token&tab=token", status_code=302)

        user_email = db.get_email_for_lab(lab["id"])
        if not user_email:
            return RedirectResponse("/login?error=No+account+found+for+this+token&tab=token", status_code=302)

        # If no password set, redirect to set-password page after login
        dest = "/my/dashboard"
        if not db.email_has_password(user_email):
            dest = "/set-password"

        response = RedirectResponse(dest, status_code=302)
        _set_session_cookie(response, user_email)
        return response


@app.get("/set-password", response_class=HTMLResponse)
def set_password_page(request: Request):
    """Page for existing users to set a password (requires active session)."""
    email = _get_session_email(request)
    if not email:
        return RedirectResponse("/login?error=Please+log+in+first+%28use+API+token%29&tab=token", status_code=302)
    msg = request.query_params.get("msg")
    error = request.query_params.get("error")
    return _render("set_password.html", _tpl_context(
        request, email=email, msg=msg, error=error, active_page="settings",
    ))


@app.post("/set-password")
def set_password_submit(
    request: Request,
    password: str = Form(""),
    password_confirm: str = Form(""),
):
    """Set password for the logged-in user."""
    email = _get_session_email(request)
    if not email:
        return RedirectResponse("/login?tab=token", status_code=302)

    client_ip = request.client.host if request.client else "unknown"
    if not _check_login_rate(client_ip):
        return RedirectResponse("/set-password?error=Too+many+attempts.+Try+again+later.", status_code=302)
    _record_login_attempt(client_ip)

    if len(password) < 8:
        return RedirectResponse("/set-password?error=Password+must+be+at+least+8+characters", status_code=302)

    if len(password) > 128:
        return RedirectResponse("/set-password?error=Password+must+be+at+most+128+characters", status_code=302)

    if password != password_confirm:
        return RedirectResponse("/set-password?error=Passwords+do+not+match", status_code=302)

    db.set_password_for_email(email, password)
    return RedirectResponse("/my/dashboard?msg=Password+set+successfully", status_code=302)


@app.get("/logout")
def logout():
    """Clear session and redirect to landing."""
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie(_SESSION_COOKIE)
    return response


@app.get("/lang/{lang_code}")
def set_language(lang_code: str, request: Request):
    """Set language preference cookie and redirect back."""
    if lang_code not in SUPPORTED_LANGUAGES:
        lang_code = "en"
    referer = request.headers.get("referer", "/")
    # Validate referer to prevent open redirect — extract path only
    from urllib.parse import urlparse
    parsed = urlparse(referer)
    # Only allow same-origin redirects: either relative path or matching host
    if parsed.netloc and parsed.netloc != urlparse(config.BASE_URL).netloc:
        referer = "/"
    elif parsed.scheme and parsed.scheme not in ("http", "https"):
        referer = "/"
    else:
        referer = parsed.path or "/"
    response = RedirectResponse(referer, status_code=302)
    response.set_cookie("labwatch_lang", lang_code, max_age=365 * 24 * 3600, path="/", samesite="lax")
    return response


@app.get("/my/add-node", response_class=HTMLResponse)
def add_node_page(request: Request):
    """Page to add a new node to the user's account."""
    email = _get_session_email(request)
    if not email:
        return RedirectResponse("/login", status_code=302)
    return _render("add_node.html", _tpl_context(request, active_page="dashboard"))


@app.post("/api/v1/my/add-node")
def add_node_api(request_body: dict, request: Request):
    """Add a new node to the logged-in user's account."""
    import re

    email = _get_session_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Not logged in")

    hostname = request_body.get("hostname", "my-server")
    hostname = re.sub(r"[^a-zA-Z0-9._-]", "", hostname)[:64] or "my-server"

    # Enforce node cap for this user's plan.
    cap = _tier_node_cap(email)
    if cap is not None and db.count_labs_for_email(email) >= cap:
        plan = db.get_plan_for_email(email, default=config.DEFAULT_PLAN)
        raise HTTPException(
            status_code=400,
            detail=f"{plan.capitalize()} plan allows {cap} nodes. Upgrade to Pro for unlimited.",
        )

    client_ip = request.client.host if request.client else "unknown"
    lab_id, token = db.signup_lab(email, hostname, client_ip)

    return {
        "lab_id": lab_id,
        "token": token,
        "config_snippet": f'api_endpoint: "{_request_base_url(request)}/api/v1"\ntoken: "{token}"\nlab_id: "{lab_id}"\ninterval: 60s',
    }


@app.get("/my/dashboard", response_class=HTMLResponse)
def user_dashboard(request: Request):
    """User's personal dashboard — shows only their labs."""
    email = _get_session_email(request)
    if not email:
        return RedirectResponse("/login", status_code=302)

    user_labs = db.get_labs_for_email(email)
    pinned_ids = set(db.get_pinned_nodes(email))
    lab_data = []
    for lab in user_labs:
        metrics = db.get_latest_metrics(lab["id"])
        system_summary = _extract_system_summary(metrics)
        docker_summary = _extract_docker_summary(metrics)
        gpu_summary = _extract_gpu_summary(metrics)
        _enrich_network_rate(system_summary, lab["id"])
        alerts = db.get_active_alerts(lab["id"])
        lab_safe = {k: v for k, v in lab.items() if k != "token"}
        lab_data.append({
            **lab_safe,
            "online": _lab_is_online(lab["last_seen"]),
            "pinned": lab["id"] in pinned_ids,
            **system_summary,
            **docker_summary,
            **gpu_summary,
            "alert_count": len(alerts),
            "critical_count": sum(1 for a in alerts if a.get("severity") == "critical"),
        })
    # Sort pinned first
    lab_data.sort(key=lambda x: x.get("pinned", False), reverse=True)

    restart_leaders = []
    for ld in lab_data:
        for c in ld.get("containers") or []:
            rc = c.get("restart_count", 0)
            if rc and rc > 0:
                restart_leaders.append({
                    "lab_id": ld["id"], "hostname": ld.get("hostname") or ld.get("name", ""),
                    "container": c.get("name", "?"), "restart_count": rc,
                })
    restart_leaders.sort(key=lambda r: r["restart_count"], reverse=True)
    restart_leaders = restart_leaders[:10]

    return _render("dashboard.html", _tpl_context(
        request, labs=lab_data, total=len(lab_data), active_page="dashboard",
        pinned_ids=pinned_ids,
        user_plan=db.get_plan_for_email(email, default=config.DEFAULT_PLAN),
        billing_enabled=config.BILLING_ENABLED,
        restart_leaders=restart_leaders,
    ))


@app.get("/my/notifications", response_class=HTMLResponse)
def user_notifications_page(request: Request):
    """User notification channels management page."""
    email = _get_session_email(request)
    if not email:
        return RedirectResponse("/login", status_code=302)
    return _render("notifications.html", _tpl_context(
        request, active_page="notifications",
    ))


@app.get("/my/alerts", response_class=HTMLResponse)
def user_alerts_page(request: Request):
    """User alert rules management page."""
    email = _get_session_email(request)
    if not email:
        return RedirectResponse("/login", status_code=302)
    thresholds = db.get_alert_thresholds(email)
    return _render("alerts.html", _tpl_context(
        request, active_page="alerts", current_thresholds=thresholds,
    ))


_ALERT_PATTERNS = {
    r"cpu.*?(\d+)": ("cpu_warning", "CPU warning"),
    r"mem(?:ory)?.*?(\d+)": ("memory_warning", "Memory warning"),
    r"disk.*?(\d+)": ("disk_warning", "Disk warning"),
    r"load.*?(\d+)": ("load_warning", "Load warning"),
    r"gpu.*?temp.*?(\d+)": ("gpu_temp_warning", "GPU temperature warning"),
    r"gpu.*?mem.*?(\d+)": ("gpu_mem_warning", "GPU memory warning"),
    r"gpu.*?util.*?(\d+)": ("gpu_util_warning", "GPU utilization warning"),
}



@app.post("/api/v1/my/alerts/generate")
def generate_alert_rule(request: Request, body: dict = None):
    """Parse a natural language alert rule into threshold config."""
    _require_session(request)
    text = (body or {}).get("text", "").strip().lower()
    if not text:
        return {"ok": False, "error": "Please describe an alert rule."}

    for pattern, (key, label) in _ALERT_PATTERNS.items():
        m = _re.search(pattern, text)
        if m:
            value = int(m.group(1))
            if value < 1 or (value > 100 and "temp" not in key and "load" not in key):
                return {"ok": False, "error": f"Threshold {value} is out of range."}
            severity = "critical" if "critical" in text else "warning"
            if severity == "critical":
                key = key.replace("_warning", "_critical")
                label = label.replace("warning", "critical")
            return {
                "ok": True,
                "summary": f"Set {label.lower()} threshold to {value}{'°C' if 'temp' in key else '%' if 'load' not in key else ''}",
                "rule": {
                    "threshold_key": key,
                    "value": value,
                    "severity": severity,
                    "metric_label": label,
                },
            }

    return {"ok": False, "error": "Could not parse. Try: 'alert me when CPU exceeds 85%'"}


@app.post("/api/v1/my/alerts/apply")
def apply_alert_rule(request: Request, body: dict = None):
    """Apply a natural language alert rule — parse + save threshold."""
    email = _require_session(request)
    result = generate_alert_rule(request, body)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "Parse failed"))

    rule = result["rule"]
    current = db.get_alert_thresholds(email)
    current[rule["threshold_key"]] = rule["value"]
    db.set_alert_thresholds(email, None, current)
    return {
        "summary": result["summary"],
        "thresholds": current,
    }


@app.get("/my/lab/{lab_id}", response_class=HTMLResponse)
def user_lab_detail(request: Request, lab_id: str):
    """User's lab detail page."""
    email = _get_session_email(request)
    if not email:
        return RedirectResponse("/login", status_code=302)

    # Verify the user owns this lab
    user_labs = db.get_labs_for_email(email)
    user_lab_ids = {lab["id"] for lab in user_labs}
    if lab_id not in user_lab_ids:
        raise HTTPException(status_code=403, detail="You don't have access to this lab")

    lab = db.get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")

    try:
        history_hours = int(request.query_params.get("hours", "24"))
    except (ValueError, TypeError):
        history_hours = 24
    history_hours = max(1, min(history_hours, _tier_retention_hours(email)))

    metrics = db.get_latest_metrics(lab_id)
    history = db.get_metrics_history(lab_id, hours=history_hours)
    alerts = db.get_active_alerts(lab_id)
    stats = db.get_lab_stats(lab_id)
    system_summary = _extract_system_summary(metrics)
    _enrich_network_rate(system_summary, lab_id)
    docker_summary = _extract_docker_summary(metrics)
    gpu_summary = _extract_gpu_summary(metrics)
    digest = db.get_latest_digest(lab_id)

    return _render("lab_detail.html", _tpl_context(
        request, lab=lab, online=_lab_is_online(lab["last_seen"]),
        gpu=gpu_summary, system=system_summary, docker=docker_summary,
        metrics=metrics, history_count=len(history), alerts=alerts,
        stats=stats, digest=digest,
    ))


@app.get("/api/v1/my/dashboard")
def user_dashboard_api(request: Request):
    """Auto-refresh data for user dashboard."""
    email = _get_session_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Not logged in")

    user_labs = db.get_labs_for_email(email)
    pinned_ids = set(db.get_pinned_nodes(email))
    lab_data = []
    total_alerts = 0
    for lab in user_labs:
        metrics = db.get_latest_metrics(lab["id"])
        system_summary = _extract_system_summary(metrics)
        docker_summary = _extract_docker_summary(metrics)
        gpu_summary = _extract_gpu_summary(metrics)
        _enrich_network_rate(system_summary, lab["id"])
        alerts = db.get_active_alerts(lab["id"])
        total_alerts += len(alerts)
        lab_safe = {k: v for k, v in lab.items() if k != "token"}
        lab_data.append({
            **lab_safe,
            "online": _lab_is_online(lab["last_seen"]),
            "pinned": lab["id"] in pinned_ids,
            **system_summary,
            **docker_summary,
            **gpu_summary,
            "alert_count": len(alerts),
            "critical_count": sum(1 for a in alerts if a.get("severity") == "critical"),
        })
    # Sort: pinned first, then by last_seen descending
    lab_data.sort(key=lambda x: (not x.get("pinned", False), x.get("last_seen", "") or ""), reverse=False)
    lab_data.sort(key=lambda x: x.get("pinned", False), reverse=True)
    return {"labs": lab_data, "total": len(lab_data), "total_alerts": total_alerts}


# ---------------------------------------------------------------------------
# User Preferences API: pins, thresholds, notifications
# ---------------------------------------------------------------------------

def _require_session(request: Request) -> str:
    email = _get_session_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Not logged in")
    return email


def _require_lab_access(email: str, lab_id: str) -> None:
    user_labs = db.get_labs_for_email(email)
    if lab_id not in {lab["id"] for lab in user_labs}:
        raise HTTPException(status_code=403, detail="You don't have access to this lab")


@app.post("/api/v1/my/pin/{lab_id}")
def pin_node(lab_id: str, request: Request):
    email = _require_session(request)
    _require_lab_access(email, lab_id)
    db.pin_node(email, lab_id)
    return {"status": "pinned"}


@app.delete("/api/v1/my/pin/{lab_id}")
def unpin_node(lab_id: str, request: Request):
    email = _require_session(request)
    _require_lab_access(email, lab_id)
    db.unpin_node(email, lab_id)
    return {"status": "unpinned"}


@app.get("/api/v1/my/pins")
def get_pins(request: Request):
    email = _require_session(request)
    return {"pinned": db.get_pinned_nodes(email)}


@app.get("/api/v1/my/thresholds")
def get_thresholds(request: Request):
    email = _require_session(request)
    return {"thresholds": db.get_alert_thresholds(email)}


@app.get("/api/v1/my/thresholds/{lab_id}")
def get_lab_thresholds(lab_id: str, request: Request):
    email = _require_session(request)
    _require_lab_access(email, lab_id)
    return {"thresholds": db.get_alert_thresholds(email, lab_id)}


@app.put("/api/v1/my/thresholds/{lab_id}")
def set_lab_thresholds(lab_id: str, request: Request, body: dict = None):
    email = _require_session(request)
    _require_lab_access(email, lab_id)
    db.set_alert_thresholds(email, lab_id, body or {})
    return {"status": "saved"}


@app.delete("/api/v1/my/thresholds/{lab_id}")
def reset_lab_thresholds(lab_id: str, request: Request):
    email = _require_session(request)
    _require_lab_access(email, lab_id)
    db.delete_alert_thresholds(email, lab_id)
    return {"status": "reset"}


_CHANNEL_REQUIRED_KEYS = {
    "webhook": ["url"],
    "ntfy": ["topic"],
    "telegram": ["bot_token", "chat_id"],
    "discord": ["webhook_url"],
    "slack": ["webhook_url"],
    "gotify": ["server", "token"],
    "pushover": ["user_key", "api_token"],
    "apprise": ["url"],
}


def _validate_channel_config(channel_type: str, config: dict) -> list[str]:
    """Return list of missing required config keys, empty if valid."""
    required = _CHANNEL_REQUIRED_KEYS.get(channel_type, [])
    return [k for k in required if not config.get(k)]


@app.get("/api/v1/my/notifications")
def list_user_notifications(request: Request):
    """List notification channels owned by the current user."""
    email = _require_session(request)
    channels = [_redact_channel_config(c) for c in db.list_user_notification_channels(email)]
    return {"channels": channels, "total": len(channels)}


@app.post("/api/v1/my/notifications")
def create_user_notification(request: Request, body: dict = None):
    """Create a user-owned notification channel."""
    email = _require_session(request)
    body = body or {}
    name = body.get("name")
    channel_type = body.get("channel_type")
    cfg = body.get("config", {})
    min_severity = body.get("min_severity", "warning")

    if not name or not channel_type:
        raise HTTPException(status_code=400, detail="name and channel_type are required")
    if channel_type not in ("webhook", "ntfy", "telegram", "discord", "slack", "gotify", "pushover", "apprise"):
        raise HTTPException(status_code=400, detail="Unsupported channel_type")
    if min_severity not in ("info", "warning", "critical"):
        raise HTTPException(status_code=400, detail="min_severity must be info, warning, or critical")

    # Validate required config keys per channel type
    missing = _validate_channel_config(channel_type, cfg)
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required config: {', '.join(missing)}")

    channel_id = db.add_user_notification_channel(email, name, channel_type, cfg, min_severity)
    return {"id": channel_id, "status": "created", "channel": {"id": channel_id, "name": name, "channel_type": channel_type}}


@app.delete("/api/v1/my/notifications/{channel_id}")
def delete_user_notification(channel_id: int, request: Request):
    """Delete a user-owned notification channel."""
    email = _require_session(request)
    deleted = db.delete_user_notification_channel(email, channel_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Channel not found")
    return {"status": "deleted", "id": channel_id}


@app.post("/api/v1/my/notifications/test-inline")
def test_user_notification_inline(request: Request, body: dict = None):
    """Send a test notification without saving the channel (UI preview)."""
    _require_session(request)
    body = body or {}
    channel_type = body.get("type") or body.get("channel_type", "")
    cfg = body.get("config", {})
    if not channel_type:
        raise HTTPException(status_code=400, detail="type is required")
    from notifications import send_test_notification_inline
    return send_test_notification_inline(channel_type, cfg)


@app.post("/api/v1/my/notifications/{channel_id}/test")
def test_user_notification(channel_id: int, request: Request):
    """Send a test notification to a user-owned channel."""
    email = _require_session(request)
    # Verify ownership
    channels = db.list_user_notification_channels(email)
    if not any(c["id"] == channel_id for c in channels):
        raise HTTPException(status_code=404, detail="Channel not found")
    from notifications import send_test_notification
    result = send_test_notification(channel_id)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Test failed"))
    return result


@app.get("/api/v1/my/notification-prefs")
def get_notification_prefs(request: Request):
    email = _require_session(request)
    return {"prefs": db.get_notification_prefs(email)}


@app.put("/api/v1/my/notification-prefs")
def set_notification_prefs(request: Request, body: dict = None):
    email = _require_session(request)
    db.set_notification_prefs(email, body or {})
    return {"status": "saved"}


@app.delete("/api/v1/my/lab/{lab_id}")
def user_delete_lab(request: Request, lab_id: str):
    """Delete a node belonging to the authenticated user."""
    email = _require_session(request)
    # Verify the lab belongs to this user
    if not db.email_owns_lab(email, lab_id):
        raise HTTPException(status_code=404, detail="Lab not found")
    db.delete_lab(lab_id)
    return {"status": "deleted", "lab_id": lab_id}


@app.delete("/api/v1/my/account")
def user_delete_account(request: Request):
    """Delete the authenticated user's account and all associated data (GDPR right to erasure)."""
    email = _require_session(request)
    db.delete_account(email)
    response = JSONResponse(content={"status": "deleted"})
    response.delete_cookie(_SESSION_COOKIE)
    return response


@app.get("/my/lab/{lab_id}/history")
def user_lab_history(request: Request, lab_id: str, hours: int = 24):
    """User's lab metrics history API."""
    hours = max(1, min(hours, 8760))  # Clamp to 1h..1year
    email = _get_session_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Not logged in")

    user_labs = db.get_labs_for_email(email)
    user_lab_ids = {lab["id"] for lab in user_labs}
    if lab_id not in user_lab_ids:
        raise HTTPException(status_code=403, detail="You don't have access to this lab")

    # Reuse the same history logic as admin
    history = db.get_metrics_history(lab_id, hours=hours)
    timestamps, cpu_data, memory_data, disk_data, load_data = [], [], [], [], []
    net_rx_data, net_tx_data = [], []
    gpu_timestamps, gpu_util_data, gpu_mem_data, gpu_temp_data = [], [], [], []
    system_entries = []

    for entry in reversed(history):
        data = entry.get("data", {})
        ts = entry.get("timestamp", "")
        if entry.get("metric_type") == "system":
            system_entries.append(entry)
            cpu = data.get("cpu", {})
            mem = data.get("memory", {})
            disks = data.get("disk", [])
            load_avg = data.get("load_average", {})
            timestamps.append(ts)
            cpu_data.append(cpu.get("total_percent", 0) or 0)
            memory_data.append(mem.get("used_percent", 0) or 0)
            disk_pct = disks[0].get("used_percent", 0) if isinstance(disks, list) and disks else 0
            disk_data.append(disk_pct or 0)
            if isinstance(load_avg, dict):
                load_data.append(load_avg.get("load1", 0) or 0)
            elif isinstance(load_avg, (list, tuple)) and load_avg:
                load_data.append(load_avg[0] or 0)
            else:
                load_data.append(0)
        elif entry.get("metric_type") == "gpu":
            devices = data.get("devices", [])
            if devices and isinstance(devices, list):
                dev = devices[0]
                gpu_timestamps.append(ts)
                gpu_util_data.append(dev.get("utilization_percent", 0) or 0)
                gpu_mem = dev.get("memory", {})
                gpu_mem_data.append(gpu_mem.get("used_percent", 0) or 0 if isinstance(gpu_mem, dict) else 0)
                gpu_temp_data.append(dev.get("temperature_celsius", 0) or 0)

    # Compute network rates from consecutive samples
    for i in range(len(system_entries)):
        if i == 0:
            net_rx_data.append(0)
            net_tx_data.append(0)
            continue
        try:
            from datetime import datetime as _dt
            cur, prev = system_entries[i], system_entries[i - 1]
            t_cur = _dt.fromisoformat(cur["timestamp"])
            t_prev = _dt.fromisoformat(prev["timestamp"])
            delta_s = (t_cur - t_prev).total_seconds()
            if delta_s <= 0:
                net_rx_data.append(0)
                net_tx_data.append(0)
                continue
            cur_net = cur["data"].get("network", [])
            prev_net = prev["data"].get("network", [])
            prev_map = {n["interface"]: n for n in prev_net}
            rx_d = tx_d = 0
            for iface in cur_net:
                if iface.get("interface") == "lo":
                    continue
                p = prev_map.get(iface["interface"], {})
                rx_d += max(0, iface.get("bytes_recv", 0) - p.get("bytes_recv", 0))
                tx_d += max(0, iface.get("bytes_sent", 0) - p.get("bytes_sent", 0))
            net_rx_data.append(min(round(rx_d * 8 / delta_s / 1_000_000, 2), 1000))
            net_tx_data.append(min(round(tx_d * 8 / delta_s / 1_000_000, 2), 1000))
        except Exception:
            net_rx_data.append(0)
            net_tx_data.append(0)

    # Remove counter-reset spikes: replace values > 10x median with 0
    for arr in (net_rx_data, net_tx_data):
        nonzero = sorted(v for v in arr if v > 0)
        if len(nonzero) >= 3:
            median = nonzero[len(nonzero) // 2]
            threshold = max(median * 10, 100)
            for i in range(len(arr)):
                if arr[i] > threshold:
                    arr[i] = 0

    result = {"timestamps": timestamps, "cpu": cpu_data, "memory": memory_data, "disk": disk_data, "load": load_data, "net_rx": net_rx_data, "net_tx": net_tx_data}
    if gpu_timestamps:
        result.update({"gpu_timestamps": gpu_timestamps, "gpu_utilization": gpu_util_data, "gpu_memory": gpu_mem_data, "gpu_temperature": gpu_temp_data})
    return result


# ---------------------------------------------------------------------------
# Agent API
# ---------------------------------------------------------------------------

@app.post("/api/v1/register", response_model=RegisterResponse)
def register_agent(body: RegisterRequest, x_admin_secret: Optional[str] = Header(None)):
    # Registration requires admin secret during alpha
    if not x_admin_secret or not hmac.compare_digest(x_admin_secret, config.ADMIN_SECRET):
        raise HTTPException(status_code=403, detail="Registration closed during alpha. Contact admin.")
    lab_id, token = db.register_lab(body.hostname, body.os, body.arch, body.agent_version)
    return RegisterResponse(
        lab_id=lab_id,
        token=token,
        message=f"Lab '{body.hostname}' registered successfully.",
    )


@app.post("/api/v1/ingest")
def ingest_metrics(body: MetricPayload, lab: dict = Depends(_require_agent_auth)):
    # Verify the lab_id in the payload matches the authenticated lab
    if body.lab_id != lab["id"]:
        raise HTTPException(
            status_code=403,
            detail="Token does not match the provided lab_id",
        )

    # Store all collector types + update last_seen in a single transaction
    collectors = body.collectors or {}
    stored_types = db.store_metrics_batch(lab["id"], collectors)

    # Run analysis
    alerts = analyze_metrics(lab["id"], collectors)

    return {
        "status": "accepted",
        "lab_id": lab["id"],
        "stored_types": stored_types,
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }


@app.get("/api/v1/status/{lab_id}")
def lab_status(lab_id: str, lab: dict = Depends(_require_agent_auth)):
    # Agent can only query its own status
    if lab_id != lab["id"]:
        raise HTTPException(status_code=403, detail="Token does not match lab_id")

    target = db.get_lab(lab_id)
    if not target:
        raise HTTPException(status_code=404, detail="Lab not found")

    metrics = db.get_latest_metrics(lab_id)
    system_summary = _extract_system_summary(metrics)
    docker_summary = _extract_docker_summary(metrics)
    active_alerts = db.get_active_alerts(lab_id)

    return {
        "lab_id": target["id"],
        "hostname": target["hostname"],
        "last_seen": target["last_seen"],
        "online": _lab_is_online(target["last_seen"]),
        "uptime_seconds": system_summary.get("uptime_seconds"),
        "cpu_percent": system_summary.get("cpu_percent"),
        "memory_percent": system_summary.get("memory_percent"),
        "disk_percent": system_summary.get("disk_percent"),
        "container_count": docker_summary.get("container_count", 0),
        "alerts": [
            {
                "id": a["id"],
                "type": a["alert_type"],
                "severity": a["severity"],
                "message": a["message"],
                "created_at": a["created_at"],
            }
            for a in active_alerts
        ],
    }






@app.get("/api/v1/dashboard/errors")
def dashboard_recent_errors(request: Request, limit: int = 10):
    """Recent error logs across all labs for the dashboard widget."""
    email = _get_session_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Not logged in")
    # Filter to only labs this user owns
    user_labs = db.get_labs_for_email(email)
    user_lab_ids = {lab["id"] for lab in user_labs}
    all_errors = db.get_recent_error_logs(limit=max(1, min(limit, 50)))
    filtered = [e for e in all_errors if e["lab_id"] in user_lab_ids]
    return {"errors": filtered}


# ---------------------------------------------------------------------------
# Log collection endpoints
# ---------------------------------------------------------------------------


@app.post("/api/v1/lab/{lab_id}/logs")
def ingest_logs(lab_id: str, body: LogIngestPayload, lab: dict = Depends(_require_agent_auth)):
    """Ingest log entries from an agent."""
    if lab_id != lab["id"]:
        raise HTTPException(status_code=403, detail="Token does not match lab_id")

    entries = [e.dict() for e in body.entries]
    count = db.store_logs(lab_id, entries)
    return {"status": "accepted", "lab_id": lab_id, "stored": count}


@app.get("/my/lab/{lab_id}/logs")
def user_lab_logs(
    request: Request,
    lab_id: str,
    limit: int = 100,
    offset: int = 0,
    level: str = None,
    source: str = None,
    since: str = None,
    until: str = None,
):
    """User-facing paginated log viewer API."""
    email = _get_session_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Not logged in")

    user_labs = db.get_labs_for_email(email)
    user_lab_ids = {lab["id"] for lab in user_labs}
    if lab_id not in user_lab_ids:
        raise HTTPException(status_code=403, detail="You don't have access to this lab")

    logs = db.get_logs(lab_id, limit=limit, offset=offset, level=level,
                       source=source, since=since, until=until)
    total = db.count_logs(lab_id, level=level, source=source)
    sources = db.get_log_sources(lab_id)

    return {
        "lab_id": lab_id,
        "logs": logs,
        "total": total,
        "sources": sources,
        "limit": limit,
        "offset": offset,
    }


@app.get("/my/lab/{lab_id}/logs/search")
def user_search_logs(request: Request, lab_id: str, q: str = "", limit: int = 50):
    """Full-text search logs for a user's lab."""
    email = _get_session_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Not logged in")

    user_labs = db.get_labs_for_email(email)
    user_lab_ids = {lab["id"] for lab in user_labs}
    if lab_id not in user_lab_ids:
        raise HTTPException(status_code=403, detail="You don't have access to this lab")

    if not q.strip():
        return {"lab_id": lab_id, "logs": [], "query": q}

    logs = db.search_logs(lab_id, q.strip(), limit=limit)
    return {"lab_id": lab_id, "logs": logs, "query": q}


@app.get("/api/v1/admin/lab/{lab_id}/logs")
def admin_lab_logs(
    lab_id: str,
    limit: int = 100,
    offset: int = 0,
    level: str = None,
    source: str = None,
    _admin: str = Depends(_require_admin),
):
    """Admin log viewer API."""
    lab = db.get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")

    logs = db.get_logs(lab_id, limit=limit, offset=offset, level=level, source=source)
    total = db.count_logs(lab_id, level=level, source=source)
    sources = db.get_log_sources(lab_id)

    return {
        "lab_id": lab_id,
        "logs": logs,
        "total": total,
        "sources": sources,
        "limit": limit,
        "offset": offset,
    }

@app.get("/api/v1/labs")
def list_labs_api(_: str = Depends(_require_admin)):
    labs = db.list_labs()
    result = []
    for lab in labs:
        stats = db.get_lab_stats(lab["id"])
        result.append({
            "lab_id": lab["id"],
            "hostname": lab["hostname"],
            "os": lab["os"],
            "arch": lab["arch"],
            "agent_version": lab["agent_version"],
            "registered_at": lab["registered_at"],
            "last_seen": lab["last_seen"],
            "online": _lab_is_online(lab["last_seen"]),
            **stats,
        })
    return {"labs": result, "total": len(result)}


# ---------------------------------------------------------------------------
# Widget API endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/widgets/uptime")
def widget_uptime(request: Request, hours: int = 24, x_admin_secret: Optional[str] = Header(None)):
    """Uptime timeline segments for all labs the user can see."""
    email = _get_session_email(request)
    is_admin = x_admin_secret and hmac.compare_digest(x_admin_secret, config.ADMIN_SECRET)
    if not email and not is_admin:
        raise HTTPException(status_code=401, detail="Authentication required")
    segments = db.get_uptime_segments(hours=hours)
    if email and not is_admin:
        user_lab_ids = {lab["id"] for lab in db.get_labs_for_email(email)}
        segments = {k: v for k, v in segments.items() if k in user_lab_ids}
    return segments


@app.get("/api/v1/widgets/alerts")
def widget_alerts(request: Request, limit: int = 20, x_admin_secret: Optional[str] = Header(None)):
    """Recent alert feed for dashboard widget."""
    limit = max(1, min(limit, 100))
    email = _get_session_email(request)
    is_admin = x_admin_secret and hmac.compare_digest(x_admin_secret, config.ADMIN_SECRET)
    if not email and not is_admin:
        raise HTTPException(status_code=401, detail="Authentication required")
    alerts = db.get_recent_alerts_feed(limit=limit)
    if email and not is_admin:
        user_lab_ids = {lab["id"] for lab in db.get_labs_for_email(email)}
        alerts = [a for a in alerts if a["lab_id"] in user_lab_ids]
    return alerts


@app.get("/api/v1/widgets/sparkline/{lab_id}/{metric}")
def widget_sparkline(request: Request, lab_id: str, metric: str, hours: int = 1, x_admin_secret: Optional[str] = Header(None), authorization: Optional[str] = Header(None)):
    """Sparkline data for a specific lab metric."""
    email = _get_session_email(request)
    is_admin = x_admin_secret and hmac.compare_digest(x_admin_secret, config.ADMIN_SECRET)
    # Also accept Bearer token auth (for API agents)
    bearer_lab = None
    if not email and not is_admin and authorization and authorization.startswith("Bearer "):
        bearer_lab = db.get_lab_by_token(authorization[7:])
    if not email and not is_admin and not bearer_lab:
        raise HTTPException(status_code=401, detail="Authentication required")
    if bearer_lab:
        # Bearer token grants access only to the lab it belongs to
        if lab_id != bearer_lab["id"]:
            raise HTTPException(status_code=403, detail="Access denied")
    elif email and not is_admin:
        user_lab_ids = {lab["id"] for lab in db.get_labs_for_email(email)}
        if lab_id not in user_lab_ids:
            raise HTTPException(status_code=403, detail="Access denied")
    if metric not in ("cpu", "memory", "disk"):
        raise HTTPException(status_code=400, detail="Invalid metric. Use: cpu, memory, disk")
    return db.get_metric_sparkline(lab_id, metric, hours=hours)


# ---------------------------------------------------------------------------
# Demo (public, no auth)
# ---------------------------------------------------------------------------

@app.get("/demo", response_class=HTMLResponse)
def demo_dashboard(request: Request):
    """Public demo with synthetic data — no auth required."""
    demo_labs = [
        {"id": "demo-1", "name": "pve-main", "hostname": "proxmox-01", "online": True,
         "cpu_percent": 23.4, "memory_percent": 61.2, "disk_percent": 44.8, "load_1m": 1.82,
         "container_count": 12, "os": "Debian 12", "arch": "x86_64",
         "net_rx_mbps": 99.2, "net_tx_mbps": 24.8,
         "alert_count": 1, "critical_count": 0,
         "last_seen": datetime.now(timezone.utc).isoformat()},
        {"id": "demo-2", "name": "docker-host", "hostname": "docker-01", "online": True,
         "cpu_percent": 8.1, "memory_percent": 38.7, "disk_percent": 29.3, "load_1m": 0.45,
         "container_count": 22, "os": "Ubuntu 24.04", "arch": "x86_64",
         "net_rx_mbps": 45.6, "net_tx_mbps": 12.3,
         "alert_count": 0, "critical_count": 0,
         "last_seen": datetime.now(timezone.utc).isoformat()},
        {"id": "demo-3", "name": "nas-storage", "hostname": "storage-01", "online": True,
         "cpu_percent": 4.2, "memory_percent": 72.8, "disk_percent": 78.1, "load_1m": 3.21,
         "container_count": 0, "os": "TrueNAS SCALE", "arch": "x86_64",
         "net_rx_mbps": 210.5, "net_tx_mbps": 185.2,
         "alert_count": 2, "critical_count": 1,
         "last_seen": datetime.now(timezone.utc).isoformat()},
        {"id": "demo-4", "name": "gpu-server", "hostname": "gpu-01", "online": False,
         "cpu_percent": 0, "memory_percent": 0, "disk_percent": 55.3, "load_1m": 0,
         "container_count": 0, "os": "Arch Linux", "arch": "x86_64",
         "alert_count": 1, "critical_count": 1,
         "last_seen": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()},
    ]
    return _render("dashboard.html", _tpl_context(
        request, labs=demo_labs, total=len(demo_labs), secret="demo", is_demo=True,
    ))


# Synthetic per-node detail data for the demo.
_DEMO_LAB_DETAILS: dict[str, dict] = {
    "demo-1": {
        "id": "demo-1", "name": "pve-main", "hostname": "proxmox-01",
        "display_name": "pve-main", "os": "Debian 12", "arch": "x86_64",
        "agent_version": "0.4.2", "registered_at": "2026-03-15T10:00:00",
        "api_token": "demo-token",
        "_online": True, "_cpu": 23.4, "_mem": 61.2, "_disk": 44.8, "_load": 1.82,
        "_containers": [
            {"name": "caddy", "image": "caddy:2-alpine", "state": "running", "cpu_percent": 0.3, "memory_usage_bytes": 44040192, "restart_count": 0},
            {"name": "pihole", "image": "pihole/pihole:latest", "state": "running", "cpu_percent": 0.1, "memory_usage_bytes": 92274688, "restart_count": 0},
            {"name": "grafana", "image": "grafana/grafana:10.4", "state": "running", "cpu_percent": 1.2, "memory_usage_bytes": 220200960, "restart_count": 0},
            {"name": "pbs", "image": "proxmox/pbs:latest", "state": "running", "cpu_percent": 0.8, "memory_usage_bytes": 163577856, "restart_count": 0},
        ],
        "_services": [
            {"name": "SSH", "port": 22, "type": "ssh", "status": "healthy", "response_time_ms": 2},
            {"name": "Proxmox VE", "port": 8006, "type": "http", "status": "healthy", "response_time_ms": 45},
            {"name": "HTTP", "port": 80, "type": "http", "status": "healthy", "response_time_ms": 8},
        ],
        "_alerts": [{"severity": "warning", "rule_name": "High memory", "message": "Memory at 61% — approaching threshold", "created_at": "2026-04-12T08:00:00"}],
    },
    "demo-2": {
        "id": "demo-2", "name": "docker-host", "hostname": "docker-01",
        "display_name": "docker-host", "os": "Ubuntu 24.04", "arch": "x86_64",
        "agent_version": "0.4.2", "registered_at": "2026-03-15T10:05:00",
        "api_token": "demo-token",
        "_online": True, "_cpu": 8.1, "_mem": 38.7, "_disk": 29.3, "_load": 0.45,
        "_containers": [
            {"name": "portainer", "image": "portainer/portainer-ce:latest", "state": "running", "cpu_percent": 0.5, "memory_usage_bytes": 125829120, "restart_count": 0},
            {"name": "uptime-kuma", "image": "louislam/uptime-kuma:1", "state": "running", "cpu_percent": 0.2, "memory_usage_bytes": 99614720, "restart_count": 0},
            {"name": "dashy", "image": "lissy93/dashy:latest", "state": "running", "cpu_percent": 0.1, "memory_usage_bytes": 67108864, "restart_count": 0},
            {"name": "nginx-proxy", "image": "jwilder/nginx-proxy:latest", "state": "running", "cpu_percent": 0.4, "memory_usage_bytes": 39845888, "restart_count": 0},
            {"name": "homeassistant", "image": "homeassistant/home-assistant:stable", "state": "running", "cpu_percent": 2.1, "memory_usage_bytes": 325058560, "restart_count": 1},
        ],
        "_services": [
            {"name": "SSH", "port": 22, "type": "ssh", "status": "healthy", "response_time_ms": 1},
            {"name": "HTTP", "port": 80, "type": "http", "status": "healthy", "response_time_ms": 5},
            {"name": "HTTPS", "port": 443, "type": "http", "status": "healthy", "response_time_ms": 12},
        ],
        "_alerts": [],
    },
    "demo-3": {
        "id": "demo-3", "name": "nas-storage", "hostname": "storage-01",
        "display_name": "nas-storage", "os": "TrueNAS SCALE", "arch": "x86_64",
        "agent_version": "0.4.1", "registered_at": "2026-03-16T14:30:00",
        "api_token": "demo-token",
        "_online": True, "_cpu": 4.2, "_mem": 72.8, "_disk": 78.1, "_load": 3.21,
        "_containers": [],
        "_services": [
            {"name": "SSH", "port": 22, "type": "ssh", "status": "healthy", "response_time_ms": 3},
            {"name": "SMB", "port": 445, "type": "smb", "status": "healthy", "response_time_ms": 6},
            {"name": "NFS", "port": 2049, "type": "nfs", "status": "healthy", "response_time_ms": 4},
        ],
        "_alerts": [
            {"severity": "critical", "rule_name": "Disk space critical", "message": "Disk at 78% — running low", "created_at": "2026-04-12T06:00:00"},
            {"severity": "warning", "rule_name": "High load", "message": "Load average 3.21 — above threshold", "created_at": "2026-04-12T07:30:00"},
        ],
    },
    "demo-4": {
        "id": "demo-4", "name": "gpu-server", "hostname": "gpu-01",
        "display_name": "gpu-server", "os": "Arch Linux", "arch": "x86_64",
        "agent_version": "0.4.0", "registered_at": "2026-03-20T09:00:00",
        "api_token": "demo-token",
        "_online": False, "_cpu": 0, "_mem": 0, "_disk": 55.3, "_load": 0,
        "_containers": [],
        "_services": [
            {"name": "SSH", "port": 22, "type": "ssh", "status": "down"},
        ],
        "_alerts": [{"severity": "critical", "rule_name": "Node offline", "message": "No heartbeat for 3 hours", "created_at": "2026-04-12T09:00:00"}],
    },
}


@app.get("/demo/lab/{lab_id}", response_class=HTMLResponse)
def demo_lab_detail(request: Request, lab_id: str):
    """Demo node detail page with synthetic data."""
    detail = _DEMO_LAB_DETAILS.get(lab_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Demo lab not found")

    now = datetime.now(timezone.utc)
    lab = {k: v for k, v in detail.items() if not k.startswith("_")}
    lab["last_seen"] = now.isoformat() if detail["_online"] else (now - timedelta(hours=3)).isoformat()

    system = {
        "cpu_percent": detail["_cpu"], "cpu_count": 4, "memory_percent": detail["_mem"],
        "disk_percent": detail["_disk"], "load_1m": detail["_load"],
        "load_5m": detail["_load"] * 0.9, "load_15m": detail["_load"] * 0.8,
        "memory_total_gb": 32.0, "memory_used_gb": 32.0 * detail["_mem"] / 100,
        "disk_total_gb": 500.0, "disk_used_gb": 500.0 * detail["_disk"] / 100,
        "uptime_seconds": 604800, "net_rx_rate": "12.4 MB/s", "net_tx_rate": "3.1 MB/s",
        "net_rx_mbps": 99.2, "net_tx_mbps": 24.8,
        "load_average": f"{detail['_load']:.2f} / {detail['_load'] * 0.9:.2f} / {detail['_load'] * 0.8:.2f}",
    }
    docker = {
        "container_count": len(detail["_containers"]),
        "containers": detail["_containers"],
    }

    # Structure metrics as the template expects (metrics.docker.data, metrics.services.data)
    demo_metrics = {
        "docker": {"data": {"containers": detail["_containers"]}},
        "services": {"data": {"services": detail.get("_services", [])}},
    }

    return _render("lab_detail.html", _tpl_context(
        request, lab=lab, online=detail["_online"],
        gpu={}, system=system, docker=docker,
        metrics=demo_metrics, history_count=24, alerts=detail["_alerts"],
        stats={"total_metrics": 1440, "oldest_metric": (now - timedelta(days=7)).isoformat()},
        secret="demo", is_demo=True,
        digest=_DEMO_DIGESTS.get(lab_id),
    ))


@app.get("/demo/lab/{lab_id}/history")
def demo_lab_history(request: Request, lab_id: str):
    """Synthetic history data for demo node detail charts."""
    import math, random

    detail = _DEMO_LAB_DETAILS.get(lab_id)
    if not detail:
        return {"timestamps": [], "cpu": [], "memory": [], "disk": [], "load": []}

    now = datetime.now(timezone.utc)
    try:
        hours = int(request.query_params.get("hours", "24"))
    except (ValueError, TypeError):
        hours = 24
    hours = max(1, min(hours, 168))
    points = min(hours * 6, 144)  # ~10min intervals, max 144 points

    timestamps, cpu_data, memory_data, disk_data, load_data = [], [], [], [], []
    net_rx_data, net_tx_data = [], []
    for i in range(points):
        t = now - timedelta(minutes=(points - i) * (hours * 60 / points))
        phase = i / points * math.pi * 4
        cpu_base = detail["_cpu"] or 15
        mem_base = detail["_mem"] or 40
        timestamps.append(t.isoformat())
        cpu_data.append(round(max(0, cpu_base + 8 * math.sin(phase) + random.uniform(-2, 2)), 1))
        memory_data.append(round(max(0, mem_base + 3 * math.sin(phase * 0.5) + random.uniform(-1, 1)), 1))
        disk_data.append(detail["_disk"])
        load_data.append(round(max(0, (detail["_load"] or 0.5) + 0.3 * math.sin(phase) + random.uniform(-0.1, 0.1)), 2))
        net_rx_data.append(round(random.uniform(0.5, 15.0), 2))
        net_tx_data.append(round(random.uniform(0.1, 5.0), 2))
    return {
        "timestamps": timestamps, "cpu": cpu_data, "memory": memory_data,
        "disk": disk_data, "load": load_data,
        "net_rx": net_rx_data, "net_tx": net_tx_data,
    }


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, x_admin_secret: Optional[str] = Header(None)):
    # Allow query param for browser access (admin is the self-hoster who owns the server)
    secret = x_admin_secret or request.query_params.get("secret") or ""
    if not hmac.compare_digest(secret, config.ADMIN_SECRET):
        return RedirectResponse("/demo", status_code=302)

    labs = db.list_labs()
    lab_data = []
    for lab in labs:
        metrics = db.get_latest_metrics(lab["id"])
        system_summary = _extract_system_summary(metrics)
        docker_summary = _extract_docker_summary(metrics)
        gpu_summary = _extract_gpu_summary(metrics)
        _enrich_network_rate(system_summary, lab["id"])
        alerts = db.get_active_alerts(lab["id"])
        lab_data.append({
            **lab,
            "online": _lab_is_online(lab["last_seen"]),
            **system_summary,
            **docker_summary,
            **gpu_summary,
            "alert_count": len(alerts),
            "critical_count": sum(1 for a in alerts if a.get("severity") == "critical"),
        })

    # Build restart leaders from container data across all labs
    restart_leaders = []
    for ld in lab_data:
        for c in ld.get("containers") or []:
            rc = c.get("restart_count", 0)
            if rc and rc > 0:
                restart_leaders.append({
                    "lab_id": ld["id"], "hostname": ld.get("hostname") or ld.get("name", ""),
                    "container": c.get("name", "?"), "restart_count": rc,
                })
    restart_leaders.sort(key=lambda r: r["restart_count"], reverse=True)
    restart_leaders = restart_leaders[:10]

    return _render("dashboard.html", _tpl_context(
        request, labs=lab_data, total=len(lab_data), secret=secret,
        restart_leaders=restart_leaders,
    ))


@app.get("/dashboard/lab/{lab_id}", response_class=HTMLResponse)
def dashboard_lab_detail(request: Request, lab_id: str, x_admin_secret: Optional[str] = Header(None)):
    secret = x_admin_secret or request.query_params.get("secret") or ""
    if not hmac.compare_digest(secret, config.ADMIN_SECRET):
        return RedirectResponse("/demo", status_code=302)

    lab = db.get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")

    # Admin view can see up to the longest tier's retention window.
    max_retention = max(
        (t.get("retention_hours") or 0) for t in config.TIER_LIMITS.values()
    )
    try:
        history_hours = int(request.query_params.get("hours", "24"))
    except (ValueError, TypeError):
        history_hours = 24
    history_hours = max(1, min(history_hours, max_retention or config.RETENTION_HOURS))

    metrics = db.get_latest_metrics(lab_id)
    history = db.get_metrics_history(lab_id, hours=history_hours)
    alerts = db.get_active_alerts(lab_id)
    stats = db.get_lab_stats(lab_id)
    system_summary = _extract_system_summary(metrics)
    _enrich_network_rate(system_summary, lab_id)
    docker_summary = _extract_docker_summary(metrics)
    gpu_summary = _extract_gpu_summary(metrics)
    digest = db.get_latest_digest(lab_id)

    return _render("lab_detail.html", _tpl_context(
        request, lab=lab, online=_lab_is_online(lab["last_seen"]),
        gpu=gpu_summary, system=system_summary, docker=docker_summary,
        metrics=metrics, history_count=len(history), alerts=alerts,
        stats=stats, secret=secret, digest=digest,
    ))


# ---------------------------------------------------------------------------
# Metrics History API
# ---------------------------------------------------------------------------

@app.get("/api/v1/labs/{lab_id}/history")
def lab_metrics_history(request: Request, lab_id: str, hours: int = 24, x_admin_secret: Optional[str] = Header(None)):
    """Return time-series metrics data for charts."""
    hours = max(1, min(hours, 8760))  # Clamp to 1h..1year
    secret = x_admin_secret or request.query_params.get("secret") or ""
    if not hmac.compare_digest(secret, config.ADMIN_SECRET):
        raise HTTPException(status_code=403, detail="Forbidden")

    history = db.get_metrics_history(lab_id, hours=hours)

    timestamps = []
    cpu_data = []
    memory_data = []
    disk_data = []
    load_data = []
    net_rx_data = []
    net_tx_data = []

    # GPU history (keyed by timestamp for alignment)
    gpu_timestamps = []
    gpu_util_data = []
    gpu_mem_data = []
    gpu_temp_data = []

    # Collect system entries for network rate calculation
    system_entries = []
    for entry in reversed(history):
        data = entry.get("data", {})
        ts = entry.get("timestamp", "")

        if entry.get("metric_type") == "system":
            system_entries.append(entry)
            cpu = data.get("cpu", {})
            mem = data.get("memory", {})
            disks = data.get("disk", [])
            load_avg = data.get("load_average", {})

            timestamps.append(ts)
            cpu_data.append(cpu.get("total_percent", 0) or 0)
            memory_data.append(mem.get("used_percent", 0) or 0)
            disk_pct = disks[0].get("used_percent", 0) if isinstance(disks, list) and disks else 0
            disk_data.append(disk_pct or 0)

            if isinstance(load_avg, dict):
                load_data.append(load_avg.get("load1", 0) or 0)
            elif isinstance(load_avg, (list, tuple)) and load_avg:
                load_data.append(load_avg[0] or 0)
            else:
                load_data.append(0)

        elif entry.get("metric_type") == "gpu":
            devices = data.get("devices", [])
            if devices and isinstance(devices, list):
                # Use first GPU for chart (most common case)
                dev = devices[0]
                gpu_timestamps.append(ts)
                gpu_util_data.append(dev.get("utilization_percent", 0) or 0)
                gpu_mem = dev.get("memory", {})
                gpu_mem_data.append(gpu_mem.get("used_percent", 0) or 0 if isinstance(gpu_mem, dict) else 0)
                gpu_temp_data.append(dev.get("temperature_celsius", 0) or 0)

    # Compute network rates from consecutive system samples
    for i in range(len(system_entries)):
        if i == 0:
            net_rx_data.append(0)
            net_tx_data.append(0)
            continue
        try:
            from datetime import datetime as _dt
            cur = system_entries[i]
            prev = system_entries[i - 1]
            t_cur = _dt.fromisoformat(cur["timestamp"])
            t_prev = _dt.fromisoformat(prev["timestamp"])
            delta_s = (t_cur - t_prev).total_seconds()
            if delta_s <= 0:
                net_rx_data.append(0)
                net_tx_data.append(0)
                continue
            cur_net = cur["data"].get("network", [])
            prev_net = prev["data"].get("network", [])
            prev_map = {n["interface"]: n for n in prev_net}
            rx_delta = tx_delta = 0
            for iface in cur_net:
                if iface.get("interface") == "lo":
                    continue
                p = prev_map.get(iface["interface"], {})
                rx_delta += max(0, iface.get("bytes_recv", 0) - p.get("bytes_recv", 0))
                tx_delta += max(0, iface.get("bytes_sent", 0) - p.get("bytes_sent", 0))
            rx_mbps = round(rx_delta * 8 / delta_s / 1_000_000, 2)
            tx_mbps = round(tx_delta * 8 / delta_s / 1_000_000, 2)
            # Clamp counter-reset spikes (cap at 1 Gbps)
            net_rx_data.append(min(rx_mbps, 1000))
            net_tx_data.append(min(tx_mbps, 1000))
        except Exception:
            net_rx_data.append(0)
            net_tx_data.append(0)

    # Remove counter-reset spikes: replace values > 10x median with 0
    for arr in (net_rx_data, net_tx_data):
        nonzero = sorted(v for v in arr if v > 0)
        if len(nonzero) >= 3:
            median = nonzero[len(nonzero) // 2]
            threshold = max(median * 10, 100)  # at least 100 Mbps
            for i in range(len(arr)):
                if arr[i] > threshold:
                    arr[i] = 0

    result = {
        "timestamps": timestamps,
        "cpu": cpu_data,
        "memory": memory_data,
        "disk": disk_data,
        "load": load_data,
        "net_rx": net_rx_data,
        "net_tx": net_tx_data,
    }

    # Include GPU data if available
    if gpu_timestamps:
        result["gpu_timestamps"] = gpu_timestamps
        result["gpu_utilization"] = gpu_util_data
        result["gpu_memory"] = gpu_mem_data
        result["gpu_temperature"] = gpu_temp_data

    return result


# ---------------------------------------------------------------------------
# Admin API
# ---------------------------------------------------------------------------

@app.get("/api/v1/admin/labs")
def admin_list_labs(_: str = Depends(_require_admin)):
    labs = db.list_labs()
    result = []
    for lab in labs:
        stats = db.get_lab_stats(lab["id"])
        lab_safe = {k: v for k, v in lab.items() if k != "token"}
        result.append({
            **lab_safe,
            "online": _lab_is_online(lab["last_seen"]),
            **stats,
        })
    return {"labs": result, "total": len(result)}


@app.get("/api/v1/admin/dashboard")
def admin_dashboard_data(_: str = Depends(_require_admin)):
    """Return enriched lab data for dashboard auto-refresh (metrics, alerts, GPU)."""
    labs = db.list_labs()
    lab_data = []
    total_alerts = 0
    for lab in labs:
        metrics = db.get_latest_metrics(lab["id"])
        system_summary = _extract_system_summary(metrics)
        docker_summary = _extract_docker_summary(metrics)
        gpu_summary = _extract_gpu_summary(metrics)
        _enrich_network_rate(system_summary, lab["id"])
        alerts = db.get_active_alerts(lab["id"])
        total_alerts += len(alerts)
        lab_safe = {k: v for k, v in lab.items() if k != "token"}
        lab_data.append({
            **lab_safe,
            "online": _lab_is_online(lab["last_seen"]),
            **system_summary,
            **docker_summary,
            **gpu_summary,
            "alert_count": len(alerts),
            "critical_count": sum(1 for a in alerts if a.get("severity") == "critical"),
        })
    return {"labs": lab_data, "total": len(lab_data), "total_alerts": total_alerts}


def _build_lab_export_response(lab_id: str, hours: int) -> JSONResponse:
    """Build the JSON export payload + download headers for a lab.
    Shared between the admin and user-scoped export routes."""
    lab = db.get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")

    history = db.get_metrics_history(lab_id, hours=hours)
    alerts = db.get_alerts_in_range(lab_id=lab_id)

    return JSONResponse(
        content={
            "lab": {
                "id": lab["id"],
                "hostname": lab["hostname"],
                "os": lab["os"],
                "arch": lab["arch"],
                "registered_at": lab["registered_at"],
            },
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "metrics_count": len(history),
            "alerts_count": len(alerts),
            "metrics": history,
            "alerts": alerts,
        },
        headers={
            "Content-Disposition": f'attachment; filename="labwatch-{lab["hostname"]}-export.json"'
        },
    )


@app.get("/api/v1/admin/lab/{lab_id}/export")
def export_lab_data(lab_id: str, hours: int = 168, _: str = Depends(_require_admin)):
    """Export metrics history for a lab as JSON (for data portability)."""
    return _build_lab_export_response(lab_id, hours)


@app.get("/api/v1/my/lab/{lab_id}/export")
def export_my_lab_data(lab_id: str, request: Request, hours: int = 168):
    """Export metrics history for a lab owned by the logged-in user."""
    email = _require_session(request)
    _require_lab_access(email, lab_id)
    return _build_lab_export_response(lab_id, hours)


def _build_lab_csv_response(lab_id: str, hours: int) -> Response:
    """Build a CSV export of system metrics for a lab."""
    lab = db.get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")

    history = db.get_metrics_history(lab_id, hours=hours)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "timestamp", "hostname", "cpu_percent", "memory_percent", "memory_used_bytes",
        "disk_percent", "load_1m", "load_5m", "load_15m", "uptime_seconds",
    ])

    for entry in history:
        if entry.get("metric_type") != "system":
            continue
        data = entry.get("data", {})
        cpu = data.get("cpu", {})
        mem = data.get("memory", {})
        load = data.get("load_average", {})
        disks = data.get("disk", [])
        disk_pct = disks[0]["used_percent"] if disks else ""
        writer.writerow([
            entry.get("timestamp", ""),
            data.get("hostname", lab.get("hostname", "")),
            round(cpu.get("total_percent", 0), 2),
            round(mem.get("used_percent", 0), 2),
            mem.get("used_bytes", ""),
            round(disk_pct, 2) if isinstance(disk_pct, (int, float)) else "",
            load.get("load1", ""),
            load.get("load5", ""),
            load.get("load15", ""),
            data.get("uptime_seconds", ""),
        ])

    csv_bytes = output.getvalue().encode("utf-8")
    hostname = lab.get("hostname", "unknown")
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="labwatch-{hostname}-metrics.csv"'
        },
    )


@app.get("/api/v1/admin/lab/{lab_id}/export.csv")
def export_lab_csv(lab_id: str, hours: int = 168, _: str = Depends(_require_admin)):
    """Export system metrics as CSV (timestamp, cpu, memory, disk, load)."""
    return _build_lab_csv_response(lab_id, hours)


@app.get("/api/v1/my/lab/{lab_id}/export.csv")
def export_my_lab_csv(lab_id: str, request: Request, hours: int = 168):
    """Export system metrics as CSV for a lab owned by the logged-in user."""
    email = _require_session(request)
    _require_lab_access(email, lab_id)
    return _build_lab_csv_response(lab_id, hours)


@app.delete("/api/v1/admin/lab/{lab_id}")
def admin_delete_lab(lab_id: str, _: str = Depends(_require_admin)):
    deleted = db.delete_lab(lab_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Lab not found")
    return {"status": "deleted", "lab_id": lab_id}


# ---------------------------------------------------------------------------
# Demo NLQ — canned responses for the public demo page
# ---------------------------------------------------------------------------


_DEMO_RESPONSES = [
    {
        "patterns": [
            r"fleet", r"summary", r"overview", r"sitrep", r"rundown",
            r"(?:fleet|overall|lab)\s+(?:status|health)",
            r"^(?:status|health)$",
            r"how(?:'s| is) (?:my |the |our )?(?:lab|fleet|cluster|everything|infra)",
            r"how(?:'s| is|are) (?:my |the |our )?(?:nodes?|servers?|machines?|things?) doing",
            r"how(?:'s| is) everything",
            r"how many (?:nodes?|servers?|machines?)",
            r"(?:nodes?|servers?)\s+(?:online|up|running|active)",
        ],
        "response": {
            "answer": (
                "4 nodes, 3 online. 3 active alerts. Needs attention \u2014 1 critical alert.\n"
                "Offline: gpu-server (last seen 3h ago).\n"
                "\n"
                "Per-node breakdown:\n"
                "  pve-main: ALERT \u2014 CPU 23%, MEM 61%, DISK 45%, 12 containers, 1 alert\n"
                "  docker-host: OK \u2014 CPU 8%, MEM 39%, DISK 29%, 22 containers\n"
                "  nas-storage: ALERT \u2014 CPU 4%, MEM 73%, DISK 78%, 2 alerts\n"
                "  gpu-server: OFFLINE \u2014 CPU 0%, MEM 0%, DISK 55%, 1 alert"
            ),
            "query_type": "fleet_overview",
            "confidence": 0.95,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"why\s+is\s+.+?\s*(?:slow|high|lagging|unresponsive)",
            r"diagnose", r"troubleshoot",
            r"what(?:'s| is)\s+(?:causing|wrong with|the\s+(?:problem|issue))",
        ],
        "response": {
            "answer": (
                "nas-storage shows I/O pressure, disk space concern. "
                "Load average (3.21) is high relative to CPU count (4) but CPU usage is low (4%). "
                "This pattern typically indicates disk or network I/O bottleneck \u2014 processes waiting on I/O rather than computing. "
                "Disk at 78.1% \u2014 approaching capacity. May cause slowdowns if filesystem is nearly full. "
                "Active alerts: disk usage 78% (warning); load average 3.21x (critical)"
            ),
            "query_type": "diagnostic",
            "confidence": 0.88,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"alert", r"show\s+(?:me\s+)?(?:all\s+)?alerts",
            r"any\s+alerts", r"active\s+alerts",
        ],
        "response": {
            "answer": (
                "3 active alerts across the fleet.\n"
                "Severity breakdown: 2 critical, 1 warning.\n"
                "  - [nas-storage] WARNING: disk usage at 78.1% exceeds 75% threshold\n"
                "  - [nas-storage] CRITICAL: load average 3.21 exceeds 3.0 threshold (4 cores)\n"
                "  - [gpu-server] CRITICAL: node offline \u2014 no metrics received for 3 hours"
            ),
            "query_type": "alerts",
            "confidence": 0.95,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"container", r"docker", r"running\s+containers",
        ],
        "response": {
            "answer": (
                "34 containers across the fleet (32 running, 2 stopped).\n"
                "\n"
                "docker-host (21/22 running):\n"
                "  - caddy: running (Up 14 days)\n"
                "  - dashy: running (Up 14 days)\n"
                "  - grafana: running (Up 12 days)\n"
                "  - jellyfin: running (Up 14 days)\n"
                "  - nextcloud: running (Up 14 days)\n"
                "  - pihole: running (Up 14 days)\n"
                "  - portainer: running (Up 14 days)\n"
                "  - uptime-kuma: running (Up 14 days)\n"
                "  - vaultwarden: running (Up 14 days)\n"
                "  - watchtower: running (Up 14 days)\n"
                "  ... and 12 more\n"
                "\n"
                "pve-main (11/12 running):\n"
                "  - prometheus: running (Up 7 days)\n"
                "  - node-exporter: running (Up 7 days)\n"
                "  ... and 10 more"
            ),
            "query_type": "containers",
            "confidence": 0.95,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"temp", r"hot", r"thermal", r"overheating", r"heat",
        ],
        "response": {
            "answer": (
                "Temperature overview (sorted hottest first):\n"
                "  pve-main: CPU 52\u00b0C, PCH 41\u00b0C\n"
                "  docker-host: CPU 38\u00b0C\n"
                "  nas-storage: CPU 44\u00b0C, Drive Bay 35\u00b0C\n"
                "  gpu-server: OFFLINE\n"
                "\n"
                "All online nodes within normal thermal range."
            ),
            "query_type": "temperature",
            "confidence": 0.92,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"what\s+needs?\s+(?:my\s+)?attention",
            r"any(?:thing)?\s+(?:wrong|broken|failing|concerning)",
            r"show\s+(?:me\s+)?(?:problems?|issues?)",
            r"needs?\s+attention",
        ],
        "response": {
            "answer": (
                "4 issues found across 2 nodes \u2014 2 need immediate attention.\n"
                "\n"
                "gpu-server [CRITICAL]:\n"
                "  - [CRITICAL] Node is OFFLINE \u2014 no metrics received for 3 hours\n"
                "\n"
                "nas-storage [CRITICAL]:\n"
                "  - [CRITICAL] High load average: 3.21 (vs 4 cores)\n"
                "  - [WARNING] Disk at 78.1%\n"
                "  - [WARNING] Alert: disk usage at 78.1% exceeds 75% threshold"
            ),
            "query_type": "attention",
            "confidence": 0.95,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"(?:which|what)\s+(?:server|node|machine)?\s*(?:uses?|has)\s+(?:the\s+)?(?:most|highest|lowest|least)\s+(?:cpu|memory|mem|ram|disk|load)",
            r"(?:most|highest|lowest|least)\s+(?:cpu|memory|mem|disk|load)",
            r"(?:top|rank|compare|sort)\s+(?:\d+\s+)?(?:by\s+)?(?:cpu|memory|mem|disk|load)(?:\s+\w+)*",
            r"(?:show|give|get)\s+(?:me\s+)?(?:cpu|memory|mem|ram)\s*(?:usage|stats|info)?",
            r"^cpu\s*(?:usage|stats)?$",
            r"^mem(?:ory)?\s*(?:usage|stats)?$",
        ],
        "response": {
            "answer": (
                "CPU usage ranking (highest first):\n"
                "  1. pve-main: 23.4%\n"
                "  2. docker-host: 8.1%\n"
                "  3. nas-storage: 4.2%\n"
                "  4. gpu-server: 0.0% [OFFLINE]\n"
                "\n"
                "pve-main is the busiest node but well within safe range."
            ),
            "query_type": "comparative",
            "confidence": 0.95,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"(?:what|anything)\s+happen",
            r"last\s+(?:night|hour|24h|day|week)",
            r"overnight", r"while\s+i\s+was\s+(?:away|gone|sleeping|asleep)",
            r"recent\s+(?:events?|changes?|activity)",
        ],
        "response": {
            "answer": (
                "Last 12 hours:\n"
                "  02:14 — gpu-server went offline (no metrics since)\n"
                "  02:14 — CRITICAL alert fired: gpu-server offline\n"
                "  03:30 — nas-storage load spiked to 4.8 (resolved at 04:15)\n"
                "  06:00 — nas-storage disk crossed 78% threshold (WARNING)\n"
                "\n"
                "Summary: 1 node went offline, 1 load spike (resolved), 1 new disk warning.\n"
                "gpu-server needs investigation — hasn't recovered in 5+ hours."
            ),
            "query_type": "time_range",
            "confidence": 0.90,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"(?:network|bandwidth|traffic|throughput|mbps|rx|tx)",
            r"(?:upload|download)\s+(?:speed|rate)",
            r"net(?:work)?\s+(?:usage|speed|rate|stats)",
        ],
        "response": {
            "answer": (
                "Network usage across all nodes:\n"
                "  docker-host: 45.8 Mbps rx / 32.1 Mbps tx\n"
                "  pve-main: 12.4 Mbps rx / 8.2 Mbps tx\n"
                "  nas-storage: 2.1 Mbps rx / 1.8 Mbps tx\n"
                "  gpu-server: OFFLINE\n"
                "\n"
                "docker-host has the highest throughput — likely serving container traffic."
            ),
            "query_type": "network",
            "confidence": 0.90,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"(?:how much|running out|low on|out of)\s+.*?(?:disk|space)",
            r"disk\s+(?:usage|space|capacity|full)",
            r"(?:how much|how many)\s+(?:ram|memory|mem)\s+(?:do\s+)?(?:i|we)\s+have(?:\s+left)?",
            r"(?:^|\s)storage\s+(?:usage|full|capacity)",
        ],
        "response": {
            "answer": (
                "Disk usage across the fleet:\n"
                "  nas-storage: 78.1% (high)\n"
                "    /mnt/data: 78.1% (412.3 GB free of 1862.6 GB)\n"
                "  gpu-server: 55.3% (moderate) [OFFLINE]\n"
                "  pve-main: 44.8% (healthy)\n"
                "    /: 44.8% (52.1 GB free of 94.4 GB)\n"
                "  docker-host: 29.3% (healthy)\n"
                "    /: 29.3% (67.4 GB free of 95.3 GB)\n"
                "\n"
                "Warnings:\n"
                "  nas-storage approaching threshold at 78.1%."
            ),
            "query_type": "capacity",
            "confidence": 0.95,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"zfs", r"zpool", r"scrub", r"pool\s+(?:status|health)",
        ],
        "response": {
            "answer": (
                "ZFS pools across the fleet (2 pools):\n"
                "  pve-main/rpool: OK \u2014 44.8% used (52.1 GB free of 94.4 GB), frag 12%\n"
                "    Last scrub: 3d ago, 0 errors\n"
                "  nas-storage/tank: OK \u2014 78.1% used (412.3 GB free of 1862.6 GB), frag 8%\n"
                "    Last scrub: 7d ago, 0 errors\n"
                "\n"
                "Warnings:\n"
                "  nas-storage/tank at 78.1% capacity"
            ),
            "query_type": "zfs",
            "confidence": 0.95,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"(?:smart|s\.m\.a\.r\.t)\.?\s*(?:status|health|data|info)",
            r"(?:disk|drive|hdd|ssd|nvme)\s+health",
            r"(?:are|is)\s+(?:my|the)\s+(?:disks?|drives?)\s+(?:healthy|ok|failing)",
            r"(?:any|are\s+there)\s+(?:disk|drive)\s+(?:failures?|errors?|problems?)",
            r"(?:failing|failed)\s+(?:disks?|drives?)",
            r"power.on.hours",
        ],
        "response": {
            "answer": (
                "S.M.A.R.T. health: 8 drives across 3 nodes\n"
                "All drives report HEALTHY.\n"
                "\n"
                "Drive details:\n"
                "  pve-main:\n"
                "    /dev/sda: Samsung SSD 870 EVO 500GB [OK, 32C, 12,841h]\n"
                "    /dev/sdb: WDC WD40EFRX-68N32N0 [OK, 34C, 28,116h]\n"
                "  docker-host:\n"
                "    /dev/sda: CT500MX500SSD1 [OK, 29C, 8,432h]\n"
                "    /dev/sdb: ST2000DM008-2UB102 [OK, 33C, 15,291h]\n"
                "  nas-storage:\n"
                "    /dev/sda: ST4000VN008-2DR166 [OK, 35C, 31,204h]\n"
                "    /dev/sdb: ST4000VN008-2DR166 [OK, 36C, 31,189h]\n"
                "    /dev/sdc: WDC WD40EFRX-68N32N0 [OK, 33C, 22,847h]\n"
                "    /dev/sdd: WDC WD40EFRX-68N32N0 [OK, 34C, 22,851h]"
            ),
            "query_type": "smart",
            "confidence": 0.95,
            "demo": True,
        },
    },
    {
        "patterns": [
            r"why\s+is\s+\S+\s+(?:slow|using|consuming|taking)",
            r"what(?:'s|\s+is)\s+wrong\s+with\s+\S+",
            r"diagnos(?:e|tic)\s+\S+",
            r"explain\s+(?:the\s+)?(?:high|low|usage|load)\s+(?:on|for)\s+\S+",
        ],
        "response": {
            "answer": (
                "Diagnostic for nas-storage:\n"
                "\n"
                "Memory at 73.2% (5.9 GB of 8 GB):\n"
                "  ZFS ARC cache: 3.1 GB (adaptive, will release under pressure)\n"
                "  Samba/NFS services: 1.2 GB\n"
                "  System + kernel: 0.8 GB\n"
                "\n"
                "This is normal for a NAS with ZFS. The ARC cache intentionally uses free RAM\n"
                "for disk caching. If applications need memory, ZFS will release ARC pages.\n"
                "\n"
                "No action needed unless you see OOM kills in the logs."
            ),
            "query_type": "diagnostic",
            "confidence": 0.9,
            "demo": True,
        },
    },
]

# Demo node-specific status responses
_DEMO_NODE_STATUS = {
    "pve-main": {
        "answer": (
            "pve-main is online. CPU 23.4%, Memory 61.2%, Disk 44.8%. "
            "Load average 1.82. Uptime: 14d 6h. "
            "11/12 containers running. "
            "1 active alert (1 warning). "
            "Latest: memory usage at 61.2% trending upward"
        ),
        "query_type": "status",
        "confidence": 0.95,
        "demo": True,
    },
    "docker-host": {
        "answer": (
            "docker-host is online. CPU 8.1%, Memory 38.7%, Disk 29.3%. "
            "Load average 0.45. Uptime: 14d 6h. "
            "21/22 containers running. "
            "No active alerts."
        ),
        "query_type": "status",
        "confidence": 0.95,
        "demo": True,
    },
    "nas-storage": {
        "answer": (
            "nas-storage is online. CPU 4.2%, Memory 72.8%, Disk 78.1%. "
            "Load average 3.21. Uptime: 42d 11h. "
            "2 active alerts (1 critical, 1 warning). "
            "Latest: load average 3.21 exceeds 3.0 threshold (4 cores)"
        ),
        "query_type": "status",
        "confidence": 0.95,
        "demo": True,
    },
    "gpu-server": {
        "answer": (
            "gpu-server is OFFLINE. Last seen 3.0 hours ago. "
            "1 active alert (1 critical). "
            "Latest: node offline \u2014 no metrics received for 3 hours"
        ),
        "query_type": "status",
        "confidence": 0.95,
        "demo": True,
    },
}




# Translated demo responses keyed by (response_index_or_node_name, lang)
_DEMO_RESPONSE_I18N: dict[tuple, str] = {
    # ── Fleet overview (index 0) ──
    (0, "de"): (
        "Fleet-Übersicht — 4 Nodes, 3 online, 1 offline\n"
        "\n"
        "  pve-main: ▲ online — CPU 23.4%, Speicher 61.2%, Disk 44.8%\n"
        "  docker-host: ▲ online — CPU 8.1%, Speicher 38.7%, Disk 29.3%\n"
        "  nas-storage: ▲ online — CPU 4.2%, Speicher 72.8%, Disk 78.1% ⚠\n"
        "  gpu-server: ▼ OFFLINE seit 3h\n"
        "\n"
        "Gesamt: 2 aktive Warnungen, 2 kritische Alarme. 34 Container laufen."
    ),
    (0, "fr"): (
        "Aperçu de la flotte — 4 nœuds, 3 en ligne, 1 hors ligne\n"
        "\n"
        "  pve-main: ▲ en ligne — CPU 23.4%, Mémoire 61.2%, Disque 44.8%\n"
        "  docker-host: ▲ en ligne — CPU 8.1%, Mémoire 38.7%, Disque 29.3%\n"
        "  nas-storage: ▲ en ligne — CPU 4.2%, Mémoire 72.8%, Disque 78.1% ⚠\n"
        "  gpu-server: ▼ HORS LIGNE depuis 3h\n"
        "\n"
        "Total: 2 avertissements actifs, 2 alertes critiques. 34 conteneurs en cours."
    ),
    (0, "es"): (
        "Resumen de la flota — 4 nodos, 3 en línea, 1 fuera de línea\n"
        "\n"
        "  pve-main: ▲ en línea — CPU 23.4%, Memoria 61.2%, Disco 44.8%\n"
        "  docker-host: ▲ en línea — CPU 8.1%, Memoria 38.7%, Disco 29.3%\n"
        "  nas-storage: ▲ en línea — CPU 4.2%, Memoria 72.8%, Disco 78.1% ⚠\n"
        "  gpu-server: ▼ FUERA DE LÍNEA hace 3h\n"
        "\n"
        "Total: 2 advertencias activas, 2 alertas críticas. 34 contenedores ejecutándose."
    ),
    (0, "uk"): (
        "Огляд флоту — 4 вузли, 3 онлайн, 1 офлайн\n"
        "\n"
        "  pve-main: ▲ онлайн — CPU 23.4%, Пам'ять 61.2%, Диск 44.8%\n"
        "  docker-host: ▲ онлайн — CPU 8.1%, Пам'ять 38.7%, Диск 29.3%\n"
        "  nas-storage: ▲ онлайн — CPU 4.2%, Пам'ять 72.8%, Диск 78.1% ⚠\n"
        "  gpu-server: ▼ ОФЛАЙН 3 год тому\n"
        "\n"
        "Всього: 2 активні попередження, 2 критичні сповіщення. 34 контейнери працюють."
    ),
    # ── Diagnostic (index 1) ──
    (1, "de"): (
        "Diagnostik für nas-storage — 2 aktive Probleme gefunden.\n"
        "\n"
        "1. Hoher Load Average: 3.21 (bei 4 Kernen = 80% gesättigt)\n"
        "   Ursache: Wahrscheinlich I/O-gebundene Last — Disk bei 78.1%\n"
        "\n"
        "2. Disk-Warnung: /mnt/data bei 78.1%\n"
        "   Empfehlung: Alte Backups bereinigen oder Speicher erweitern\n"
        "\n"
        "gpu-server ist OFFLINE seit 3h — getrennte Untersuchung nötig."
    ),
    (1, "fr"): (
        "Diagnostic de nas-storage — 2 problèmes actifs trouvés.\n"
        "\n"
        "1. Charge élevée: 3.21 (4 cœurs = 80% saturé)\n"
        "   Cause probable: charge liée aux E/S — disque à 78.1%\n"
        "\n"
        "2. Avertissement disque: /mnt/data à 78.1%\n"
        "   Recommandation: nettoyer les anciennes sauvegardes ou étendre le stockage\n"
        "\n"
        "gpu-server est HORS LIGNE depuis 3h — investigation séparée nécessaire."
    ),
    (1, "es"): (
        "Diagnóstico de nas-storage — 2 problemas activos encontrados.\n"
        "\n"
        "1. Carga alta: 3.21 (4 núcleos = 80% saturado)\n"
        "   Causa: Probable carga de E/S — disco al 78.1%\n"
        "\n"
        "2. Advertencia de disco: /mnt/data al 78.1%\n"
        "   Recomendación: limpiar backups antiguos o ampliar almacenamiento\n"
        "\n"
        "gpu-server FUERA DE LÍNEA hace 3h — requiere investigación separada."
    ),
    (1, "uk"): (
        "Діагностика nas-storage — знайдено 2 активні проблеми.\n"
        "\n"
        "1. Високе навантаження: 3.21 (4 ядра = 80% насичення)\n"
        "   Причина: Ймовірно навантаження вводу/виводу — диск на 78.1%\n"
        "\n"
        "2. Попередження диску: /mnt/data на 78.1%\n"
        "   Рекомендація: очистити старі бекапи або розширити сховище\n"
        "\n"
        "gpu-server ОФЛАЙН 3 год — потребує окремого розслідування."
    ),
    # ── Alerts (index 2) ──
    (2, "de"): (
        "4 aktive Alarme auf 2 Nodes:\n"
        "\n"
        "  [KRITISCH] gpu-server offline — keine Metriken seit 3h\n"
        "  [KRITISCH] nas-storage Load Average 3.21 überschreitet Schwellwert 3.0\n"
        "  [WARNUNG] nas-storage Disk bei 78.1% — überschreitet 75%\n"
        "  [WARNUNG] pve-main Speicher bei 61.2% — steigender Trend\n"
        "\n"
        "2 kritisch, 2 Warnungen. gpu-server braucht sofortige Aufmerksamkeit."
    ),
    (2, "fr"): (
        "4 alertes actives sur 2 nœuds :\n"
        "\n"
        "  [CRITIQUE] gpu-server hors ligne — pas de métriques depuis 3h\n"
        "  [CRITIQUE] nas-storage charge 3.21 dépasse le seuil de 3.0\n"
        "  [AVERTISSEMENT] nas-storage disque à 78.1% — dépasse 75%\n"
        "  [AVERTISSEMENT] pve-main mémoire à 61.2% — tendance à la hausse\n"
        "\n"
        "2 critiques, 2 avertissements. gpu-server nécessite une attention immédiate."
    ),
    (2, "es"): (
        "4 alertas activas en 2 nodos:\n"
        "\n"
        "  [CRÍTICO] gpu-server fuera de línea — sin métricas hace 3h\n"
        "  [CRÍTICO] nas-storage carga 3.21 supera umbral de 3.0\n"
        "  [ADVERTENCIA] nas-storage disco al 78.1% — supera 75%\n"
        "  [ADVERTENCIA] pve-main memoria al 61.2% — tendencia al alza\n"
        "\n"
        "2 críticas, 2 advertencias. gpu-server requiere atención inmediata."
    ),
    (2, "uk"): (
        "4 активні сповіщення на 2 вузлах:\n"
        "\n"
        "  [КРИТИЧНО] gpu-server офлайн — немає метрик 3 год\n"
        "  [КРИТИЧНО] nas-storage навантаження 3.21 перевищує поріг 3.0\n"
        "  [ПОПЕРЕДЖЕННЯ] nas-storage диск на 78.1% — перевищує 75%\n"
        "  [ПОПЕРЕДЖЕННЯ] pve-main пам'ять на 61.2% — зростаючий тренд\n"
        "\n"
        "2 критичні, 2 попередження. gpu-server потребує негайної уваги."
    ),
    # ── Containers (index 3) ──
    (3, "de"): (
        "34 Container auf 3 Nodes (1 offline):\n"
        "\n"
        "pve-main (11/12):\n"
        "  caddy ✓  pihole ✓  grafana ✓  pbs ✓  ...+7 weitere\n"
        "  prometheus ✗ (neu gestartet vor 23m)\n"
        "\n"
        "docker-host (21/22):\n"
        "  portainer ✓  nginx ✓  postgres ✓  redis ✓  ...+17 weitere\n"
        "  dev-api ✗ (gestoppt)\n"
        "\n"
        "nas-storage (2/2):\n"
        "  minio ✓  syncthing ✓\n"
        "\n"
        "1 Container neu gestartet, 1 gestoppt. 32/34 laufen."
    ),
    (3, "fr"): (
        "34 conteneurs sur 3 nœuds (1 hors ligne) :\n"
        "\n"
        "pve-main (11/12) :\n"
        "  caddy ✓  pihole ✓  grafana ✓  pbs ✓  ...+7 autres\n"
        "  prometheus ✗ (redémarré il y a 23m)\n"
        "\n"
        "docker-host (21/22) :\n"
        "  portainer ✓  nginx ✓  postgres ✓  redis ✓  ...+17 autres\n"
        "  dev-api ✗ (arrêté)\n"
        "\n"
        "nas-storage (2/2) :\n"
        "  minio ✓  syncthing ✓\n"
        "\n"
        "1 conteneur redémarré, 1 arrêté. 32/34 en cours."
    ),
    (3, "es"): (
        "34 contenedores en 3 nodos (1 fuera de línea):\n"
        "\n"
        "pve-main (11/12):\n"
        "  caddy ✓  pihole ✓  grafana ✓  pbs ✓  ...+7 más\n"
        "  prometheus ✗ (reiniciado hace 23m)\n"
        "\n"
        "docker-host (21/22):\n"
        "  portainer ✓  nginx ✓  postgres ✓  redis ✓  ...+17 más\n"
        "  dev-api ✗ (detenido)\n"
        "\n"
        "nas-storage (2/2):\n"
        "  minio ✓  syncthing ✓\n"
        "\n"
        "1 contenedor reiniciado, 1 detenido. 32/34 ejecutándose."
    ),
    (3, "uk"): (
        "34 контейнери на 3 вузлах (1 офлайн):\n"
        "\n"
        "pve-main (11/12):\n"
        "  caddy ✓  pihole ✓  grafana ✓  pbs ✓  ...+7 інших\n"
        "  prometheus ✗ (перезапущено 23хв тому)\n"
        "\n"
        "docker-host (21/22):\n"
        "  portainer ✓  nginx ✓  postgres ✓  redis ✓  ...+17 інших\n"
        "  dev-api ✗ (зупинено)\n"
        "\n"
        "nas-storage (2/2):\n"
        "  minio ✓  syncthing ✓\n"
        "\n"
        "1 контейнер перезапущено, 1 зупинено. 32/34 працюють."
    ),
    # ── Temperature (index 4) ──
    (4, "de"): (
        "Temperatur-Übersicht:\n"
        "  pve-main: CPU 52°C, PCH 41°C\n"
        "  docker-host: CPU 38°C\n"
        "  nas-storage: CPU 44°C, Laufwerke 35°C\n"
        "  gpu-server: OFFLINE\n"
        "\n"
        "Alle Online-Nodes im normalen Temperaturbereich."
    ),
    (4, "fr"): (
        "Aperçu des températures :\n"
        "  pve-main: CPU 52°C, PCH 41°C\n"
        "  docker-host: CPU 38°C\n"
        "  nas-storage: CPU 44°C, Baie disques 35°C\n"
        "  gpu-server: HORS LIGNE\n"
        "\n"
        "Tous les nœuds en ligne sont dans la plage thermique normale."
    ),
    (4, "es"): (
        "Resumen de temperaturas:\n"
        "  pve-main: CPU 52°C, PCH 41°C\n"
        "  docker-host: CPU 38°C\n"
        "  nas-storage: CPU 44°C, Bahía de discos 35°C\n"
        "  gpu-server: FUERA DE LÍNEA\n"
        "\n"
        "Todos los nodos en línea dentro del rango térmico normal."
    ),
    (4, "uk"): (
        "Огляд температур:\n"
        "  pve-main: CPU 52°C, PCH 41°C\n"
        "  docker-host: CPU 38°C\n"
        "  nas-storage: CPU 44°C, Відсік дисків 35°C\n"
        "  gpu-server: ОФЛАЙН\n"
        "\n"
        "Всі онлайн вузли в нормальному температурному діапазоні."
    ),
    # ── Attention (index 5) ──
    (5, "de"): (
        "4 Probleme gefunden auf 2 Nodes — 2 brauchen sofortige Aufmerksamkeit.\n"
        "\n"
        "gpu-server [KRITISCH]:\n"
        "  - [KRITISCH] Node ist OFFLINE — keine Metriken seit 3 Stunden\n"
        "\n"
        "nas-storage [KRITISCH]:\n"
        "  - [KRITISCH] Hoher Load Average: 3.21 (bei 4 Kernen)\n"
        "  - [WARNUNG] Disk bei 78.1%\n"
        "  - [WARNUNG] Alarm: Disk-Nutzung bei 78.1% überschreitet 75%"
    ),
    (5, "fr"): (
        "4 problèmes trouvés sur 2 nœuds — 2 nécessitent une attention immédiate.\n"
        "\n"
        "gpu-server [CRITIQUE] :\n"
        "  - [CRITIQUE] Nœud HORS LIGNE — pas de métriques depuis 3 heures\n"
        "\n"
        "nas-storage [CRITIQUE] :\n"
        "  - [CRITIQUE] Charge élevée: 3.21 (4 cœurs)\n"
        "  - [AVERTISSEMENT] Disque à 78.1%\n"
        "  - [AVERTISSEMENT] Alerte: utilisation disque 78.1% dépasse 75%"
    ),
    (5, "es"): (
        "4 problemas encontrados en 2 nodos — 2 necesitan atención inmediata.\n"
        "\n"
        "gpu-server [CRÍTICO]:\n"
        "  - [CRÍTICO] Nodo FUERA DE LÍNEA — sin métricas hace 3 horas\n"
        "\n"
        "nas-storage [CRÍTICO]:\n"
        "  - [CRÍTICO] Carga alta: 3.21 (4 núcleos)\n"
        "  - [ADVERTENCIA] Disco al 78.1%\n"
        "  - [ADVERTENCIA] Alerta: uso de disco 78.1% supera 75%"
    ),
    (5, "uk"): (
        "4 проблеми знайдено на 2 вузлах — 2 потребують негайної уваги.\n"
        "\n"
        "gpu-server [КРИТИЧНО]:\n"
        "  - [КРИТИЧНО] Вузол ОФЛАЙН — немає метрик 3 години\n"
        "\n"
        "nas-storage [КРИТИЧНО]:\n"
        "  - [КРИТИЧНО] Високе навантаження: 3.21 (4 ядра)\n"
        "  - [ПОПЕРЕДЖЕННЯ] Диск на 78.1%\n"
        "  - [ПОПЕРЕДЖЕННЯ] Сповіщення: диск 78.1% перевищує 75%"
    ),
    # ── Comparative (index 6) ──
    (6, "de"): (
        "CPU-Nutzung (absteigend):\n"
        "  1. pve-main: 23.4%\n"
        "  2. docker-host: 8.1%\n"
        "  3. nas-storage: 4.2%\n"
        "  4. gpu-server: 0.0% [OFFLINE]\n"
        "\n"
        "pve-main ist der aktivste Node, aber im sicheren Bereich."
    ),
    (6, "fr"): (
        "Utilisation CPU (décroissant) :\n"
        "  1. pve-main: 23.4%\n"
        "  2. docker-host: 8.1%\n"
        "  3. nas-storage: 4.2%\n"
        "  4. gpu-server: 0.0% [HORS LIGNE]\n"
        "\n"
        "pve-main est le nœud le plus actif mais dans la plage sûre."
    ),
    (6, "es"): (
        "Uso de CPU (descendente):\n"
        "  1. pve-main: 23.4%\n"
        "  2. docker-host: 8.1%\n"
        "  3. nas-storage: 4.2%\n"
        "  4. gpu-server: 0.0% [FUERA DE LÍNEA]\n"
        "\n"
        "pve-main es el nodo más activo pero dentro del rango seguro."
    ),
    (6, "uk"): (
        "Використання CPU (спадання):\n"
        "  1. pve-main: 23.4%\n"
        "  2. docker-host: 8.1%\n"
        "  3. nas-storage: 4.2%\n"
        "  4. gpu-server: 0.0% [ОФЛАЙН]\n"
        "\n"
        "pve-main — найактивніший вузол, але в безпечному діапазоні."
    ),
    # ── Recent events (index 7) ──
    (7, "de"): (
        "Letzte 12 Stunden:\n"
        "  02:14 — gpu-server ging offline (seitdem keine Metriken)\n"
        "  02:14 — KRITISCHER Alarm: gpu-server offline\n"
        "  03:30 — nas-storage Last stieg auf 4.8 (gelöst um 04:15)\n"
        "  06:00 — nas-storage Disk überschritt 78% (WARNUNG)\n"
        "\n"
        "Zusammenfassung: 1 Node offline, 1 Last-Spitze (gelöst), 1 neue Disk-Warnung.\n"
        "gpu-server braucht Untersuchung — seit 5+ Stunden nicht erholt."
    ),
    (7, "fr"): (
        "Dernières 12 heures :\n"
        "  02:14 — gpu-server est passé hors ligne (aucune métrique depuis)\n"
        "  02:14 — Alerte CRITIQUE: gpu-server hors ligne\n"
        "  03:30 — nas-storage charge a grimpé à 4.8 (résolu à 04:15)\n"
        "  06:00 — nas-storage disque a dépassé 78% (AVERTISSEMENT)\n"
        "\n"
        "Résumé: 1 nœud hors ligne, 1 pic de charge (résolu), 1 nouvel avertissement disque.\n"
        "gpu-server nécessite une investigation — pas de récupération depuis 5h+."
    ),
    (7, "es"): (
        "Últimas 12 horas:\n"
        "  02:14 — gpu-server se desconectó (sin métricas desde entonces)\n"
        "  02:14 — Alerta CRÍTICA: gpu-server fuera de línea\n"
        "  03:30 — nas-storage carga subió a 4.8 (resuelto a las 04:15)\n"
        "  06:00 — nas-storage disco superó 78% (ADVERTENCIA)\n"
        "\n"
        "Resumen: 1 nodo fuera de línea, 1 pico de carga (resuelto), 1 nueva advertencia de disco.\n"
        "gpu-server necesita investigación — sin recuperación hace 5h+."
    ),
    (7, "uk"): (
        "Останні 12 годин:\n"
        "  02:14 — gpu-server перейшов офлайн (з тих пір немає метрик)\n"
        "  02:14 — КРИТИЧНЕ сповіщення: gpu-server офлайн\n"
        "  03:30 — nas-storage навантаження зросло до 4.8 (вирішено о 04:15)\n"
        "  06:00 — nas-storage диск перевищив 78% (ПОПЕРЕДЖЕННЯ)\n"
        "\n"
        "Підсумок: 1 вузол офлайн, 1 стрибок навантаження (вирішено), 1 нове попередження диску.\n"
        "gpu-server потребує розслідування — не відновився 5+ годин."
    ),
    # ── Network (index 8) ──
    (8, "de"): (
        "Netzwerk-Nutzung aller Nodes:\n"
        "  proxmox-01: 12.4 Mbps rx / 8.2 Mbps tx\n"
        "  docker-01: 45.8 Mbps rx / 32.1 Mbps tx\n"
        "  storage-01: 2.1 Mbps rx / 1.8 Mbps tx\n"
        "  gpu-01: OFFLINE\n"
        "\n"
        "docker-01 hat den höchsten Durchsatz — wahrscheinlich Container-Traffic."
    ),
    (8, "fr"): (
        "Utilisation réseau de tous les nœuds :\n"
        "  proxmox-01: 12.4 Mbps rx / 8.2 Mbps tx\n"
        "  docker-01: 45.8 Mbps rx / 32.1 Mbps tx\n"
        "  storage-01: 2.1 Mbps rx / 1.8 Mbps tx\n"
        "  gpu-01: HORS LIGNE\n"
        "\n"
        "docker-01 a le débit le plus élevé — probablement du trafic conteneur."
    ),
    (8, "es"): (
        "Uso de red de todos los nodos:\n"
        "  proxmox-01: 12.4 Mbps rx / 8.2 Mbps tx\n"
        "  docker-01: 45.8 Mbps rx / 32.1 Mbps tx\n"
        "  storage-01: 2.1 Mbps rx / 1.8 Mbps tx\n"
        "  gpu-01: FUERA DE LÍNEA\n"
        "\n"
        "docker-01 tiene el mayor rendimiento — probablemente tráfico de contenedores."
    ),
    (8, "uk"): (
        "Використання мережі всіх вузлів:\n"
        "  proxmox-01: 12.4 Mbps rx / 8.2 Mbps tx\n"
        "  docker-01: 45.8 Mbps rx / 32.1 Mbps tx\n"
        "  storage-01: 2.1 Mbps rx / 1.8 Mbps tx\n"
        "  gpu-01: ОФЛАЙН\n"
        "\n"
        "docker-01 має найвищу пропускну здатність — ймовірно трафік контейнерів."
    ),
    # ── Disk (index 9) ──
    (9, "de"): (
        "Disk-Nutzung der gesamten Flotte:\n"
        "  nas-storage: 78.1% (hoch)\n"
        "    /mnt/data: 78.1% (412.3 GB frei von 1862.6 GB)\n"
        "  gpu-server: 55.3% (mittel) [OFFLINE]\n"
        "  pve-main: 44.8% (gesund)\n"
        "    /: 44.8% (52.1 GB frei von 94.4 GB)\n"
        "  docker-host: 29.3% (gesund)\n"
        "    /: 29.3% (67.4 GB frei von 95.3 GB)\n"
        "\n"
        "Warnungen:\n"
        "  nas-storage nähert sich dem Schwellwert bei 78.1%."
    ),
    (9, "fr"): (
        "Utilisation disque de toute la flotte :\n"
        "  nas-storage: 78.1% (élevé)\n"
        "    /mnt/data: 78.1% (412.3 Go libres sur 1862.6 Go)\n"
        "  gpu-server: 55.3% (modéré) [HORS LIGNE]\n"
        "  pve-main: 44.8% (sain)\n"
        "    /: 44.8% (52.1 Go libres sur 94.4 Go)\n"
        "  docker-host: 29.3% (sain)\n"
        "    /: 29.3% (67.4 Go libres sur 95.3 Go)\n"
        "\n"
        "Avertissements :\n"
        "  nas-storage approche du seuil à 78.1%."
    ),
    (9, "es"): (
        "Uso de disco de toda la flota:\n"
        "  nas-storage: 78.1% (alto)\n"
        "    /mnt/data: 78.1% (412.3 GB libres de 1862.6 GB)\n"
        "  gpu-server: 55.3% (moderado) [FUERA DE LÍNEA]\n"
        "  pve-main: 44.8% (saludable)\n"
        "    /: 44.8% (52.1 GB libres de 94.4 GB)\n"
        "  docker-host: 29.3% (saludable)\n"
        "    /: 29.3% (67.4 GB libres de 95.3 GB)\n"
        "\n"
        "Advertencias:\n"
        "  nas-storage acercándose al umbral en 78.1%."
    ),
    (9, "uk"): (
        "Використання диску всього флоту:\n"
        "  nas-storage: 78.1% (високе)\n"
        "    /mnt/data: 78.1% (412.3 ГБ вільно з 1862.6 ГБ)\n"
        "  gpu-server: 55.3% (помірне) [ОФЛАЙН]\n"
        "  pve-main: 44.8% (здоровий)\n"
        "    /: 44.8% (52.1 ГБ вільно з 94.4 ГБ)\n"
        "  docker-host: 29.3% (здоровий)\n"
        "    /: 29.3% (67.4 ГБ вільно з 95.3 ГБ)\n"
        "\n"
        "Попередження:\n"
        "  nas-storage наближається до порогу на 78.1%."
    ),
    # ── Node-specific statuses ──
    ("pve-main", "de"): "pve-main ist online. CPU 23.4%, Speicher 61.2%, Disk 44.8%. Load Average 1.82. Uptime: 14T 6h. 11/12 Container laufen. 1 aktiver Alarm (1 Warnung). Letzter: Speichernutzung bei 61.2% steigend",
    ("pve-main", "fr"): "pve-main est en ligne. CPU 23.4%, Mémoire 61.2%, Disque 44.8%. Charge 1.82. Uptime: 14j 6h. 11/12 conteneurs. 1 alerte active (1 avertissement). Dernière: mémoire à 61.2% en hausse",
    ("pve-main", "es"): "pve-main está en línea. CPU 23.4%, Memoria 61.2%, Disco 44.8%. Carga 1.82. Uptime: 14d 6h. 11/12 contenedores. 1 alerta activa (1 advertencia). Última: memoria al 61.2% en aumento",
    ("pve-main", "uk"): "pve-main онлайн. CPU 23.4%, Пам'ять 61.2%, Диск 44.8%. Навантаження 1.82. Аптайм: 14д 6г. 11/12 контейнерів. 1 активне сповіщення (1 попередження). Останнє: пам'ять 61.2% зростає",

    ("docker-host", "de"): "docker-host ist online. CPU 8.1%, Speicher 38.7%, Disk 29.3%. Load Average 0.45. Uptime: 14T 6h. 21/22 Container laufen. Keine aktiven Alarme.",
    ("docker-host", "fr"): "docker-host est en ligne. CPU 8.1%, Mémoire 38.7%, Disque 29.3%. Charge 0.45. Uptime: 14j 6h. 21/22 conteneurs. Aucune alerte active.",
    ("docker-host", "es"): "docker-host está en línea. CPU 8.1%, Memoria 38.7%, Disco 29.3%. Carga 0.45. Uptime: 14d 6h. 21/22 contenedores. Sin alertas activas.",
    ("docker-host", "uk"): "docker-host онлайн. CPU 8.1%, Пам'ять 38.7%, Диск 29.3%. Навантаження 0.45. Аптайм: 14д 6г. 21/22 контейнерів. Немає активних сповіщень.",

    ("nas-storage", "de"): "nas-storage ist online. CPU 4.2%, Speicher 72.8%, Disk 78.1%. Load Average 3.21. Uptime: 42T 11h. 2 aktive Alarme (1 kritisch, 1 Warnung). Letzter: Load Average 3.21 überschreitet 3.0 (4 Kerne)",
    ("nas-storage", "fr"): "nas-storage est en ligne. CPU 4.2%, Mémoire 72.8%, Disque 78.1%. Charge 3.21. Uptime: 42j 11h. 2 alertes actives (1 critique, 1 avertissement). Dernière: charge 3.21 dépasse 3.0 (4 cœurs)",
    ("nas-storage", "es"): "nas-storage está en línea. CPU 4.2%, Memoria 72.8%, Disco 78.1%. Carga 3.21. Uptime: 42d 11h. 2 alertas activas (1 crítica, 1 advertencia). Última: carga 3.21 supera 3.0 (4 núcleos)",
    ("nas-storage", "uk"): "nas-storage онлайн. CPU 4.2%, Пам'ять 72.8%, Диск 78.1%. Навантаження 3.21. Аптайм: 42д 11г. 2 активні сповіщення (1 критичне, 1 попередження). Останнє: навантаження 3.21 перевищує 3.0 (4 ядра)",

    ("gpu-server", "de"): "gpu-server ist OFFLINE. Zuletzt gesehen vor 3.0 Stunden. 1 aktiver Alarm (1 kritisch). Letzter: Node offline — keine Metriken seit 3 Stunden",
    ("gpu-server", "fr"): "gpu-server est HORS LIGNE. Vu pour la dernière fois il y a 3.0 heures. 1 alerte active (1 critique). Dernière: nœud hors ligne — pas de métriques depuis 3 heures",
    ("gpu-server", "es"): "gpu-server está FUERA DE LÍNEA. Visto por última vez hace 3.0 horas. 1 alerta activa (1 crítica). Última: nodo fuera de línea — sin métricas hace 3 horas",
    ("gpu-server", "uk"): "gpu-server ОФЛАЙН. Останній раз бачено 3.0 години тому. 1 активне сповіщення (1 критичне). Останнє: вузол офлайн — немає метрик 3 години",
}

_DEMO_NOISE_WORDS = {
    # English
    "status", "state", "health", "how", "is", "the", "my", "doing",
    "check", "ok", "okay", "what", "whats", "hows", "about", "s",
    # German
    "wie", "geht", "es", "ist", "der", "die", "das", "mein", "meine", "meinem",
    "zustand", "gesundheit",
    # French
    "comment", "va", "est", "le", "la", "les", "mon", "ma", "mes", "quel", "quelle",
    "etat", "sante",
    # Spanish
    "como", "esta", "el", "mi", "mis", "que", "cual", "estado", "salud",
    # Ukrainian
    "як", "мій", "моя", "стан", "що",
}

# Multilingual patterns that map to the same demo response indices.
# Each tuple: (pattern_regex, index_into_DEMO_RESPONSES)
_DEMO_I18N_PATTERNS = [
    # Fleet overview (index 0)
    (r"(?:flotte|zusammenfassung|überblick|übersicht|wie geht.* (?:lab|cluster|fleet|infra)|wie viele (?:nodes?|knoten|server))", 0),  # DE
    (r"(?:flotte|résumé|aperçu|comment va .* (?:lab|cluster|fleet|infra)|combien de (?:nœuds?|noeuds?|serveurs?))", 0),  # FR
    (r"(?:flota|resumen|cómo (?:está|va) .* (?:lab|cluster|fleet|infra)|cuántos (?:nodos?|servidores?))", 0),  # ES
    (r"(?:флот|огляд|як .* (?:lab|cluster|fleet|кластер|інфра)|скільки (?:вузлів|серверів|нод))", 0),  # UK
    # Diagnostic (index 1)
    (r"(?:warum|wieso|weshalb).+(?:langsam|hoch|problem|fehler)", 1),  # DE
    (r"(?:pourquoi|diagnostiquer).+(?:lent|problème|erreur)", 1),  # FR
    (r"(?:por\s*qué|diagnosticar).+(?:lento|problema|error)", 1),  # ES
    (r"(?:чому|діагност).+(?:повільн|проблем)", 1),  # UK
    # Alerts (index 2)
    (r"(?:warnung|alarm|meldung|aktive)", 2),  # DE
    (r"(?:alerte|avertissement|toutes les alertes)", 2),  # FR
    (r"(?:alerta|advertencia|todas las alertas)", 2),  # ES
    (r"(?:сповіщення|попередження|тривог)", 2),  # UK
    # Containers (index 3)
    (r"(?:container|docker|laufende)", 3),  # DE (container same)
    (r"(?:conteneur|docker)", 3),  # FR
    (r"(?:contenedor|docker)", 3),  # ES
    (r"(?:контейнер|докер)", 3),  # UK
    # Temperature (index 4)
    (r"(?:temperatur|hitze|hei[sß]{1,2}|thermal|überhitz)", 4),  # DE
    (r"(?:température|chaud|thermique|surchauffe)", 4),  # FR
    (r"(?:temperatura|caliente|térmico|sobrecalent)", 4),  # ES
    (r"(?:температур|гаряч|перегрів)", 4),  # UK
    # Attention (index 5)
    (r"(?:aufmerksamkeit|was (?:stimmt nicht|ist (?:kaputt|falsch))|probleme)", 5),  # DE
    (r"(?:attention|qu.est.ce qui (?:ne va pas|cloche)|problème)", 5),  # FR
    (r"(?:atención|qué (?:está mal|pasa)|problema)", 5),  # ES
    (r"(?:уваг[аиі]|потребує|що не так|проблем)", 5),  # UK
    # Comparative (index 6)
    (r"(?:welch|höchst|meiste|niedrigst|vergleich).+(?:cpu|speicher|ram|disk|last)", 6),  # DE
    (r"(?:quel|plus|moins|comparer).+(?:cpu|mémoire|ram|disque|charge)", 6),  # FR
    (r"(?:cuál|más|menos|comparar).+(?:cpu|memoria|ram|disco|carga)", 6),  # ES
    (r"(?:який|найбільш|найменш|порівн).+(?:cpu|пам|диск|навант)", 6),  # UK
    # Recent events (index 7)
    (r"(?:letzte|gestern|über nacht|was ist passiert|kürzlich)", 7),  # DE
    (r"(?:dernier|hier|cette nuit|que s.est.il passé|récent)", 7),  # FR
    (r"(?:último|ayer|anoche|qué pasó|reciente)", 7),  # ES
    (r"(?:останн|вчора|що сталося|нещодавно)", 7),  # UK
    # Network (index 8)
    (r"(?:netzwerk|bandbreite|datenverkehr|durchsatz)", 8),  # DE
    (r"(?:réseau|bande passante|trafic|débit)", 8),  # FR
    (r"(?:red|ancho de banda|tráfico|rendimiento)", 8),  # ES
    (r"(?:мережа|пропускна|трафік)", 8),  # UK
    # Disk (index 9)
    (r"(?:festplatte|speicherplatz|platte voll|speicher(?:nutzung|kapazität))", 9),  # DE
    (r"(?:disque|espace|stockage|capacité)", 9),  # FR
    (r"(?:disco|espacio|almacenamiento|capacidad)", 9),  # ES
    (r"(?:диск|місце|сховищ|ємніст)", 9),  # UK
]

_DEMO_FALLBACK_I18N = {
    "de": (
        "Ich habe deine Frage verstanden, habe aber keine vorgefertigte Demo-Antwort dafür. "
        "Im Produktivbetrieb analysiert labwatch deine echten Fleet-Metriken und beantwortet "
        "natürlichsprachliche Fragen zu deiner Infrastruktur.\n\n"
        "Probiere:\n"
        '  - "fleet status"\n  - "was braucht Aufmerksamkeit?"\n'
        '  - "zeig mir alle Alarme"\n  - "welcher Node nutzt am meisten CPU?"'
    ),
    "fr": (
        "J'ai compris ta question mais je n'ai pas de réponse démo prédéfinie. "
        "En production, labwatch analyse les vraies métriques de ta flotte et répond "
        "aux questions en langage naturel sur ton infrastructure.\n\n"
        "Essaie :\n"
        '  - "fleet status"\n  - "qu\'est-ce qui nécessite attention ?"\n'
        '  - "montre-moi toutes les alertes"\n  - "quel nœud utilise le plus de CPU ?"'
    ),
    "es": (
        "Entendí tu pregunta pero no tengo una respuesta demo predefinida. "
        "En producción, labwatch analiza las métricas reales de tu flota y responde "
        "preguntas en lenguaje natural sobre tu infraestructura.\n\n"
        "Prueba:\n"
        '  - "fleet status"\n  - "¿qué necesita atención?"\n'
        '  - "muéstrame todas las alertas"\n  - "¿qué nodo usa más CPU?"'
    ),
    "uk": (
        "Я зрозумів твоє питання, але не маю заготовленої демо-відповіді. "
        "У продакшені labwatch аналізує реальні метрики твого флоту та відповідає "
        "на запитання природною мовою про твою інфраструктуру.\n\n"
        "Спробуй:\n"
        '  - "fleet status"\n  - "що потребує уваги?"\n'
        '  - "покажи всі сповіщення"\n  - "який вузол найбільше CPU?"'
    ),
}


def _detect_demo_lang(q: str) -> str:
    """Best-effort language detection from a short demo query."""
    # Check for Cyrillic → Ukrainian
    if _re.search(r'[\u0400-\u04ff]', q):
        return "uk"
    # German markers
    if _re.search(r'\b(?:wie|ist|mein|welch|zeig|warnung|alarm|knoten|festplatte|überblick)\b', q):
        return "de"
    # French markers
    if _re.search(r"\b(?:comment|quel|montre|alerte|nœuds?|réseau|disque|température|combien|serveur)\b", q):
        return "fr"
    # Spanish markers
    if _re.search(r"\b(?:cómo|cuál|cuántos?|muestra|alerta|nodo|disco|temperatura|como\s+est[aá]|cual|cuantos?|estado\s+de|resumen|flota)\b", q):
        return "es"
    return "en"


def _demo_nlq_response(question: str) -> dict:
    """Return a canned NLQ response for demo mode.

    Supports English, German, French, Spanish, and Ukrainian input.
    Responses are returned in the detected language when a translation
    is available (de/fr/es/uk), otherwise English.
    """
    q = question.lower().strip().rstrip("?")
    lang = _detect_demo_lang(q)

    # If the query is just a node name (possibly with "status", "health", etc.),
    # return the node-specific response directly.
    _demo_node_names = list(_DEMO_NODE_STATUS.keys())
    q_words = _re.sub(r'[^a-z0-9\s\u0400-\u04ff-]', '', q).split()
    q_meaningful = [w for w in q_words if w not in _DEMO_NOISE_WORDS]

    # Also match partial/short names (e.g. "pve" → "pve-main", "nas" → "nas-storage")
    _demo_aliases = {"pve": "pve-main", "nas": "nas-storage", "gpu": "gpu-server", "docker": "docker-host"}
    for node_name in _demo_node_names:
        matched = node_name.lower() in q
        if not matched:
            for alias, target in _demo_aliases.items():
                if target == node_name and alias in q_words:
                    matched = True
                    break
        if matched:
            remaining = [w for w in q_meaningful if w not in (node_name.lower(), *_demo_aliases.keys())]
            if not remaining or all(w in _DEMO_NOISE_WORDS for w in remaining):
                response = _DEMO_NODE_STATUS[node_name]
                if lang != "en" and (node_name, lang) in _DEMO_RESPONSE_I18N:
                    return {**response, "answer": _DEMO_RESPONSE_I18N[(node_name, lang)]}
                return response

    # Check English patterns first
    for i, entry in enumerate(_DEMO_RESPONSES):
        for pattern in entry["patterns"]:
            if _re.search(pattern, q):
                resp = entry["response"]
                if lang != "en" and (i, lang) in _DEMO_RESPONSE_I18N:
                    return {**resp, "answer": _DEMO_RESPONSE_I18N[(i, lang)]}
                return resp

    # Check multilingual patterns
    for pattern, idx in _DEMO_I18N_PATTERNS:
        if _re.search(pattern, q, _re.IGNORECASE):
            resp = _DEMO_RESPONSES[idx]["response"]
            if lang != "en" and (idx, lang) in _DEMO_RESPONSE_I18N:
                return {**resp, "answer": _DEMO_RESPONSE_I18N[(idx, lang)]}
            return resp

    # Check for node-specific status queries as final catch
    for node_name, response in _DEMO_NODE_STATUS.items():
        if node_name.lower() in q:
            if lang != "en" and (node_name, lang) in _DEMO_RESPONSE_I18N:
                return {**response, "answer": _DEMO_RESPONSE_I18N[(node_name, lang)]}
            return response

    # Fallback — use translated version if available
    fallback_text = _DEMO_FALLBACK_I18N.get(lang, (
        "I understood your question but don't have a canned demo response for it. "
        "In production, labwatch analyzes your real fleet metrics to answer natural "
        "language questions about your infrastructure.\n"
        "\n"
        "Try asking:\n"
        '  - "fleet status"\n'
        '  - "what needs attention?"\n'
        '  - "show me all alerts"\n'
        '  - "why is nas-storage slow?"\n'
        '  - "what containers are running?"\n'
        '  - "how hot is everything?"\n'
        '  - "which node uses the most cpu?"\n'
        '  - "how much disk space do I have?"'
    ))
    return {
        "answer": fallback_text,
        "query_type": "fallback",
        "confidence": 0.0,
        "demo": True,
    }


def _ember_personality(result: dict) -> dict:
    """Add Ember's personality to NLQ responses."""
    answer = result.get("answer", "")
    qtype = result.get("query_type", "")

    # Prefix based on query type
    prefixes = {
        "fleet_overview": "here's the lay of the land — ",
        "attention": "let me check... ",
        "temperature": "thermal check — ",
        "status": "checking on that — ",
        "comparative": "running the numbers — ",
        "diagnostics": "let me dig in — ",
        "capacity": "storage check — ",
        "time_range": "looking back — ",
        "alerts": "heads up — ",
    }
    prefix = prefixes.get(qtype, "")

    # Suffix based on content sentiment
    if "all clear" in answer.lower() or "healthy" in answer.lower() or "grade: a" in answer.lower():
        suffix = "\n\nyour lab is vibing. nothing to worry about."
    elif "critical" in answer.lower() or "offline" in answer.lower():
        suffix = "\n\nmight want to look into that."
    elif "warning" in answer.lower() or "high" in answer.lower():
        suffix = "\n\nnot urgent, but keep an eye on it."
    else:
        suffix = ""

    result = dict(result)
    result["answer"] = prefix + answer + suffix
    result["ember_mode"] = True
    return result


@app.post("/api/v1/query")
def natural_language_query(
    request: Request,
    request_body: dict,
    x_admin_secret: Optional[str] = Header(None),
):
    """Answer a natural language question about the infrastructure.

    Auth paths:
      - "demo" secret → canned public-demo responses
      - admin secret → global scope (all labs)
      - valid session cookie → scoped to that user's labs
      - otherwise → 403

    Responses are localized via `detect_language(request)` so the NLQ
    widget on the user dashboard answers in the same language as the UI.
    """
    secret = x_admin_secret or request_body.get("secret")

    question = request_body.get("question", "").strip()[:500]  # cap length (DoS/ReDoS protection)
    if not question:
        raise HTTPException(status_code=400, detail="question is required")

    # Demo mode: return canned responses for the public demo page
    if secret == "demo":
        result = _demo_nlq_response(question)
        return result

    lang = detect_language(request)

    from nlq import query

    ember_mode = request_body.get("ember_mode", False)

    if secret and hmac.compare_digest(secret, config.ADMIN_SECRET):
        result = query(question, lang=lang)
        if ember_mode:
            result = _ember_personality(result)
        return result

    # Session-auth fallback: user dashboard widget sends an empty secret.
    email = _get_session_email(request)
    if email:
        result = query(question, email=email, lang=lang)
        if ember_mode:
            result = _ember_personality(result)
        return result

    raise HTTPException(status_code=403, detail="Forbidden")


_DEMO_DIGESTS = {
    "demo-1": {
        "hostname": "pve-main", "grade": "A",
        "created_at": "2026-04-12T10:00:00", "period_start": "2026-04-05T10:00:00", "period_end": "2026-04-12T10:00:00",
        "summary": "pve-main had a quiet last 24 hours. Running well below capacity.\n\n"
                   "CPU usage averaged just 23% \u2014 significant headroom for additional workloads.\n"
                   "Memory is moderate at 61% but stable with no swapping detected.\n"
                   "Disk sits at 45% \u2014 plenty of room.\n\n"
                   "**Health Grade: A**\n\n"
                   "CPU: 23.4% avg, peaked at 41.2%, currently 23.4%\n"
                   "Memory: 61.2% avg, range 58.1%-64.3%, currently 61.2%\n"
                   "Disk: 44.8% avg, currently 44.8%\n"
                   "Alerts: Clean \u2014 zero alerts this period",
    },
    "demo-2": {
        "hostname": "docker-host", "grade": "B+",
        "created_at": "2026-04-12T10:00:00", "period_start": "2026-04-05T10:00:00", "period_end": "2026-04-12T10:00:00",
        "summary": "docker-host is running warm but stable. 14 containers active with no restart loops.\n\n"
                   "CPU averaged 67% \u2014 busy but not concerning. Memory at 78% is the main constraint.\n"
                   "Consider migrating lower-priority containers if memory pressure increases.\n\n"
                   "**Health Grade: B+**\n\n"
                   "CPU: 67.8% avg, peaked at 84.1%, currently 67.8%\n"
                   "Memory: 78.4% avg, range 71.2%-82.6%, currently 78.4%\n"
                   "Disk: 62.1% avg, currently 62.1%\n"
                   "Alerts: 1 warning (memory_high) \u2014 auto-resolved",
    },
    "demo-3": {
        "hostname": "nas-storage", "grade": "B-",
        "created_at": "2026-04-12T10:00:00", "period_start": "2026-04-05T10:00:00", "period_end": "2026-04-12T10:00:00",
        "summary": "nas-storage needs attention. Disk usage at 81% is approaching the warning threshold.\n\n"
                   "CPU and memory are fine \u2014 this is a storage-bound node. Load average of 4.2 suggests sustained I/O.\n"
                   "Recommend reviewing large files or scheduling cleanup before hitting 85%.\n\n"
                   "**Health Grade: B-**\n\n"
                   "CPU: 12.1% avg, peaked at 28.4%, currently 12.1%\n"
                   "Memory: 45.6% avg, range 42.1%-48.9%, currently 45.6%\n"
                   "Disk: 81.3% avg, currently 81.3%\n"
                   "Alerts: 1 active warning (disk_high at 81%)",
    },
    "demo-4": {
        "hostname": "gpu-server", "grade": "A-",
        "created_at": "2026-04-12T10:00:00", "period_start": "2026-04-05T10:00:00", "period_end": "2026-04-12T10:00:00",
        "summary": "gpu-server is healthy with moderate GPU utilization. Good balance of compute and idle time.\n\n"
                   "CPU at 34% with GPU inference running smoothly. Memory comfortable at 52%.\n"
                   "GPU temp steady at 62\u00b0C \u2014 well within safe range.\n\n"
                   "**Health Grade: A-**\n\n"
                   "CPU: 34.2% avg, peaked at 56.8%, currently 34.2%\n"
                   "Memory: 52.8% avg, range 48.1%-57.4%, currently 52.8%\n"
                   "Disk: 55.4% avg, currently 55.4%\n"
                   "GPU: 72% utilization, 62\u00b0C, 6.2/8.0 GB VRAM\n"
                   "Alerts: Clean \u2014 zero alerts this period",
    },
}


@app.post("/api/v1/admin/digest/{lab_id}")
def generate_lab_digest(lab_id: str, hours: int = 168, x_admin_secret: Optional[str] = Header(None)):
    """Generate an intelligence digest for a specific lab."""
    hours = max(1, min(hours, 8760))  # cap to 1 year
    # Demo mode: return synthetic digest
    if x_admin_secret == "demo" and lab_id.startswith("demo-"):
        d = _DEMO_DIGESTS.get(lab_id)
        if d:
            return {"lab_id": lab_id, "hostname": d["hostname"], "grade": d["grade"], "summary": d["summary"], "hours": hours}
        raise HTTPException(status_code=404, detail="Demo lab not found")
    # Real mode: require admin
    if not x_admin_secret or not hmac.compare_digest(x_admin_secret, config.ADMIN_SECRET):
        raise HTTPException(status_code=401, detail="Invalid admin secret")
    from digest import generate_digest
    lab = db.get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")
    return generate_digest(lab_id, lab["hostname"], hours=hours)


@app.post("/api/v1/admin/digest")
def generate_fleet_digest_endpoint(hours: int = 168, _: str = Depends(_require_admin)):
    """Generate an intelligence digest for the entire fleet."""
    hours = max(1, min(hours, 8760))  # cap to 1 year
    from digest import generate_fleet_digest
    return generate_fleet_digest(hours=hours)


@app.get("/api/v1/admin/digest/{lab_id}")
def get_lab_digest(lab_id: str, _: str = Depends(_require_admin)):
    """Get the latest stored digest for a lab."""
    digest = db.get_latest_digest(lab_id)
    if not digest:
        raise HTTPException(status_code=404, detail="No digest found")
    return digest


# ---------------------------------------------------------------------------
# Notification Channels (Admin)
# ---------------------------------------------------------------------------

@app.get("/api/v1/admin/notifications")
def list_notification_channels(_: str = Depends(_require_admin)):
    """List all notification channels."""
    channels = [_redact_channel_config(c) for c in db.list_notification_channels()]
    return {"channels": channels, "total": len(channels)}


@app.post("/api/v1/admin/notifications")
def create_notification_channel(
    request_body: dict,
    _: str = Depends(_require_admin),
):
    """Create a new notification channel."""
    name = request_body.get("name")
    channel_type = request_body.get("channel_type")
    config = request_body.get("config", {})
    min_severity = request_body.get("min_severity", "warning")

    if not name or not channel_type:
        raise HTTPException(status_code=400, detail="name and channel_type are required")
    if channel_type not in ("webhook", "ntfy", "telegram", "discord", "slack", "gotify", "pushover", "apprise"):
        raise HTTPException(status_code=400, detail="Unsupported channel_type")
    if min_severity not in ("info", "warning", "critical"):
        raise HTTPException(status_code=400, detail="min_severity must be 'info', 'warning', or 'critical'")

    missing = _validate_channel_config(channel_type, config)
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required config: {', '.join(missing)}")

    channel_id = db.add_notification_channel(name, channel_type, config, min_severity)
    return {"id": channel_id, "status": "created"}


@app.put("/api/v1/admin/notifications/{channel_id}")
def update_notification_channel(
    channel_id: int,
    request_body: dict,
    _: str = Depends(_require_admin),
):
    """Update a notification channel."""
    updated = db.update_notification_channel(channel_id, **request_body)
    if not updated:
        raise HTTPException(status_code=404, detail="Channel not found")
    return {"status": "updated", "id": channel_id}


@app.delete("/api/v1/admin/notifications/{channel_id}")
def delete_notification_channel(
    channel_id: int,
    _: str = Depends(_require_admin),
):
    """Delete a notification channel."""
    deleted = db.delete_notification_channel(channel_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Channel not found")
    return {"status": "deleted", "id": channel_id}


@app.post("/api/v1/admin/notifications/{channel_id}/test")
def test_notification_channel(
    channel_id: int,
    _: str = Depends(_require_admin),
):
    """Send a test notification."""
    from notifications import send_test_notification
    result = send_test_notification(channel_id)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Test failed"))
    return result


# ---------------------------------------------------------------------------
# Billing — Stripe checkout + webhook
# ---------------------------------------------------------------------------

def _stripe_client():
    """Return the stripe module with the API key bound, or None if billing
    is disabled. Keeping this lazy lets the process start even when the
    Stripe SDK isn't installed — a 503 is returned at request time instead.
    """
    if not config.BILLING_ENABLED:
        return None
    try:
        import stripe  # type: ignore
    except ImportError:
        return None
    stripe.api_key = config.STRIPE_SECRET_KEY
    return stripe


@app.post("/api/v1/billing/checkout")
def billing_checkout(request_body: dict, request: Request):
    """Start a Stripe Checkout Session for the logged-in user's plan upgrade.

    Body: {"plan": "pro" | "business"}
    Returns: {"url": "https://checkout.stripe.com/..."}
    """
    stripe = _stripe_client()
    if stripe is None:
        raise HTTPException(status_code=503, detail="Billing is not configured")

    email = _get_session_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Not logged in")

    plan = (request_body.get("plan") or "").strip().lower()
    price_id = config.STRIPE_PRICE_BY_PLAN.get(plan)
    if not price_id:
        raise HTTPException(
            status_code=400,
            detail=f"Plan '{plan}' is not available for self-service checkout",
        )

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            customer_email=email,
            client_reference_id=email,
            metadata={"email": email, "plan": plan},
            subscription_data={"metadata": {"email": email, "plan": plan}},
            success_url=f"{_request_base_url(request)}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{_request_base_url(request)}/billing/cancel",
            allow_promotion_codes=True,
        )
    except Exception:
        logging.getLogger("labwatch").exception("Stripe checkout session create failed")
        raise HTTPException(status_code=502, detail="Could not start checkout")

    return {"url": session.url, "session_id": session.id}


@app.post("/api/v1/billing/webhook")
async def billing_webhook(request: Request):
    """Receive Stripe webhook events. Only upgrades the plan on
    `checkout.session.completed` — the redirect success_url is informational
    only, never trusted as an upgrade trigger.
    """
    logger = logging.getLogger("labwatch")
    stripe = _stripe_client()
    if stripe is None:
        raise HTTPException(status_code=503, detail="Billing is not configured")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, config.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except Exception as e:
        # Covers stripe.error.SignatureVerificationError without importing the
        # error class (version-safe across SDK revs).
        logger.warning(f"Stripe webhook signature rejected: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")
    event_type = event.get("type") if isinstance(event, dict) else event["type"]
    event_id = event.get("id") if isinstance(event, dict) else event["id"]

    # Atomic idempotency: claim the event so only one handler processes it.
    # Prevents TOCTOU race when Stripe retries or delivers concurrently.
    if not db.claim_stripe_event(event_id):
        logger.info(f"Stripe event {event_id} already processed, skipping")
        return {"ok": True, "noop": "duplicate"}

    try:
        result = await _handle_stripe_event(event_type, event, logger)
    except Exception:
        # Return 200 on internal errors so Stripe doesn't retry endlessly.
        # The loud log lets us investigate manually.
        logger.exception(f"Stripe webhook handler failed for {event_type} ({event_id})")
        result = {"ok": True, "error": "internal", "event": event_type}

    return result


async def _handle_stripe_event(event_type: str, event, logger):
    """Dispatch a verified Stripe event. Raises on unexpected failures so the
    caller can log + still return 200 to Stripe."""

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata") or {}
        email = (metadata.get("email") or session.get("customer_email") or session.get("client_reference_id") or "").strip().lower()
        plan = (metadata.get("plan") or "").lower()
        if not email:
            logger.warning(f"Stripe checkout.session.completed with no email: {session.get('id')}")
            return {"ok": True, "noop": "no email"}
        if plan not in config.STRIPE_PRICE_BY_PLAN or plan == config.DEFAULT_PLAN:
            logger.error(f"Stripe event with missing/invalid plan {plan!r} for {email} ({session.get('id')})")
            return {"ok": True, "noop": "invalid plan"}
        rows = db.set_plan_for_email(email, plan)
        if rows == 0:
            logger.error(f"Stripe upgrade: {email} → {plan} matched 0 rows ({session.get('id')})")
        else:
            logger.info(f"Stripe upgrade: {email} → {plan} ({rows} rows updated)")
        if rows > 0:
            await asyncio.to_thread(
                mailer.send_plan_upgrade_receipt, email, plan, session.get("id", "")
            )
        return {"ok": True, "email": email, "plan": plan, "rows": rows}

    if event_type == "customer.subscription.deleted":
        sub = event["data"]["object"]
        metadata = sub.get("metadata") or {}
        email = (metadata.get("email") or "").strip().lower()
        if not email:
            logger.warning(f"Stripe subscription.deleted with no email in metadata: {sub.get('id')}")
            return {"ok": True, "noop": "no email in metadata"}
        rows = db.set_plan_for_email(email, config.DEFAULT_PLAN)
        logger.info(f"Stripe cancellation: {email} → {config.DEFAULT_PLAN} ({rows} rows)")
        if rows > 0:
            await asyncio.to_thread(mailer.send_plan_downgrade_notice, email)
        return {"ok": True, "email": email, "plan": config.DEFAULT_PLAN, "rows": rows}

    if event_type == "invoice.payment_failed":
        invoice = event["data"]["object"]
        sub_id = invoice.get("subscription")
        customer_email = invoice.get("customer_email")
        attempt = invoice.get("attempt_count", 0)
        logger.warning(f"Stripe payment failed: {customer_email} sub={sub_id} attempt={attempt}")
        # After 3 failed attempts Stripe will cancel the subscription, which
        # triggers customer.subscription.deleted.  We only log here to stay
        # aware — the actual downgrade happens on deletion.
        return {"ok": True, "event": event_type, "email": customer_email}

    # Unhandled event types are acknowledged with 200 so Stripe doesn't retry.
    return {"ok": True, "event": event_type}


@app.get("/billing/success", response_class=HTMLResponse)
def billing_success(request: Request):
    """Landing page after a successful checkout redirect. The actual plan
    flip happens in the webhook — this page just thanks the user and
    points them at their dashboard.
    """
    return _render("billing_result.html", _tpl_context(
        request, outcome="success",
    ))


@app.get("/billing/cancel", response_class=HTMLResponse)
def billing_cancel(request: Request):
    """Landing page if the user cancels/closes the checkout page."""
    return _render("billing_result.html", _tpl_context(
        request, outcome="cancel",
    ))


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=config.HOST,
        port=config.PORT,
    )
