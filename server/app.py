"""Homelab Intelligence (labwatch) — FastAPI server.

Receives metrics from lightweight Go agents on customer homelabs,
stores them in SQLite, provides REST endpoints and a simple dashboard.
"""

import asyncio
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(name)s: %(message)s")

import config
import database as db
import mailer
from analyzer import analyze_metrics
from i18n import detect_language, get_translations, SUPPORTED_LANGUAGES, LANGUAGE_NAMES
from models import MetricPayload, RegisterRequest, RegisterResponse, SignupRequest

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="labwatch",
    description="Homelab Intelligence monitoring service",
    version="0.1.0",
    docs_url="/api-docs",
    redoc_url="/api-redoc",
)

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _md_bold(text: str) -> str:
    """Convert markdown **bold** and ### headings to HTML."""
    import re
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


async def _periodic_purge():
    """Run the tier-aware purge every 6 hours."""
    logger = logging.getLogger("labwatch")
    while True:
        await asyncio.sleep(6 * 3600)
        _run_tier_purge(logger)


@app.on_event("startup")
def startup():
    global _purge_task
    db.init_db()
    _run_tier_purge(logging.getLogger("labwatch"))
    _purge_task = asyncio.get_event_loop().create_task(_periodic_purge())


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
    logging.getLogger("labwatch").error(f"Internal error on {request.url}: {exc}")
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
    if not x_admin_secret or x_admin_secret != config.ADMIN_SECRET:
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
        "base_url": config.BASE_URL,
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
        return (datetime.utcnow() - ts) < timedelta(minutes=threshold_minutes)
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
        pass


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
    return templates.TemplateResponse("landing.html", _tpl_context(request))


@app.get("/docs", response_class=HTMLResponse)
def api_docs(request: Request):
    return templates.TemplateResponse("docs.html", _tpl_context(request, active_page="docs"))


@app.get("/about", response_class=HTMLResponse)
def about_page(request: Request):
    return templates.TemplateResponse("about.html", _tpl_context(request, active_page="about"))


@app.get("/support", response_class=HTMLResponse)
def support_page(request: Request):
    return templates.TemplateResponse("support.html", _tpl_context(request, active_page="support"))


@app.get("/self-hosted", response_class=HTMLResponse)
def self_hosted_page(request: Request):
    return templates.TemplateResponse("self_hosted.html", _tpl_context(request, active_page="self_hosted"))


@app.get("/pricing")
def pricing_redirect():
    # Pricing lives as a section on the landing page. A canonical /pricing
    # path exists because docs + NLQ link to it (cold-look audit 2026-04-11).
    return RedirectResponse("/#pricing", status_code=302)


@app.get("/health")
def health():
    return {"status": "ok", "service": "labwatch", "version": "0.1.0"}


@app.get("/install.sh", response_class=PlainTextResponse)
def install_script():
    """Serve the install script with BASE_URL pre-configured."""
    # Check local copy first (Docker), then sibling agent dir (dev)
    script_path = Path(__file__).parent / "install.sh"
    if not script_path.exists():
        script_path = Path(__file__).parent.parent / "agent" / "install.sh"
    if not script_path.exists():
        raise HTTPException(status_code=404, detail="Install script not found")
    script = script_path.read_text()
    script = script.replace(
        'BASE_URL="${LABWATCH_URL:-https://labwatch.dev}"',
        f'BASE_URL="${{LABWATCH_URL:-{config.BASE_URL}}}"',
    )
    return script


@app.get("/download/{filename}")
def download_binary(filename: str):
    """Serve agent binary downloads."""
    from fastapi.responses import FileResponse
    dist_dir = Path(__file__).parent / "dist"
    file_path = (dist_dir / filename).resolve()
    if not str(file_path).startswith(str(dist_dir.resolve())):
        raise HTTPException(status_code=400, detail="Invalid filename")
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
    if body.password is not None and len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    # Sanitize hostname
    hostname = re.sub(r"[^a-zA-Z0-9._-]", "", body.hostname)[:64] or "my-server"

    lab_id, token = db.signup_lab(body.email, hostname, client_ip, body.password)

    return {
        "lab_id": lab_id,
        "token": token,
        "install_command": f'curl -fsSL {config.BASE_URL}/install.sh | sudo bash',
        "config_snippet": (
            f"api_endpoint: \"{config.BASE_URL}/api/v1\"\n"
            f"token: \"{token}\"\n"
            f"lab_id: \"{lab_id}\"\n"
            f"interval: 60s\n"
            f"docker:\n"
            f"  enabled: true\n"
            f"  socket: /var/run/docker.sock"
        ),
        "next_steps": [
            f"Run: curl -fsSL {config.BASE_URL}/install.sh | sudo bash",
            f"Save config to /etc/labwatch/config.yaml",
            "Run: sudo systemctl enable --now labwatch",
            f"View your dashboard at {config.BASE_URL}/my/dashboard",
        ],
    }


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    """Self-service signup page."""
    return templates.TemplateResponse("signup.html", _tpl_context(request))


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
    return templates.TemplateResponse("login.html", _tpl_context(request, error=error, active_page="login"))


@app.post("/login")
def login_submit(
    token: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    method: str = Form("token"),
):
    """Authenticate user by token or email+password, set session cookie."""

    if method == "email":
        # Email + password login
        email = email.strip()
        if not email or not password:
            return RedirectResponse("/login?error=Please+enter+email+and+password&tab=email", status_code=302)

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
    return templates.TemplateResponse("set_password.html", _tpl_context(
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

    if len(password) < 8:
        return RedirectResponse("/set-password?error=Password+must+be+at+least+8+characters", status_code=302)

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
    response = RedirectResponse(referer, status_code=302)
    response.set_cookie("labwatch_lang", lang_code, max_age=365 * 24 * 3600, samesite="lax")
    return response


@app.get("/my/add-node", response_class=HTMLResponse)
def add_node_page(request: Request):
    """Page to add a new node to the user's account."""
    email = _get_session_email(request)
    if not email:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("add_node.html", _tpl_context(request, active_page="dashboard"))


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
        "config_snippet": f'api_endpoint: "{config.BASE_URL}/api/v1"\ntoken: "{token}"\nlab_id: "{lab_id}"\ninterval: 60s',
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
        lab_data.append({
            **lab,
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

    return templates.TemplateResponse("dashboard.html", _tpl_context(
        request, labs=lab_data, total=len(lab_data), active_page="dashboard",
        pinned_ids=pinned_ids,
        user_plan=db.get_plan_for_email(email, default=config.DEFAULT_PLAN),
        billing_enabled=config.BILLING_ENABLED,
    ))


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

    history_hours = int(request.query_params.get("hours", "24"))
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

    return templates.TemplateResponse("lab_detail.html", _tpl_context(
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
        lab_data.append({
            **lab,
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
def set_lab_thresholds(lab_id: str, request: Request, body: dict = {}):
    email = _require_session(request)
    _require_lab_access(email, lab_id)
    db.set_alert_thresholds(email, lab_id, body)
    return {"status": "saved"}


@app.delete("/api/v1/my/thresholds/{lab_id}")
def reset_lab_thresholds(lab_id: str, request: Request):
    email = _require_session(request)
    db.delete_alert_thresholds(email, lab_id)
    return {"status": "reset"}


@app.get("/api/v1/my/notification-prefs")
def get_notification_prefs(request: Request):
    email = _require_session(request)
    return {"prefs": db.get_notification_prefs(email)}


@app.put("/api/v1/my/notification-prefs")
def set_notification_prefs(request: Request, body: dict = {}):
    email = _require_session(request)
    db.set_notification_prefs(email, body)
    return {"status": "saved"}


@app.get("/my/lab/{lab_id}/history")
def user_lab_history(request: Request, lab_id: str, hours: int = 24):
    """User's lab metrics history API."""
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
    if not x_admin_secret or x_admin_secret != config.ADMIN_SECRET:
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

    # Store each collector type separately
    collectors = body.collectors or {}
    stored_types = []
    for metric_type, data in collectors.items():
        db.store_metrics(lab["id"], metric_type, data)
        stored_types.append(metric_type)

    # Update last seen
    db.update_last_seen(lab["id"])

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
def widget_uptime(request: Request, hours: int = 24):
    """Uptime timeline segments for all labs the user can see."""
    email = _get_session_email(request)
    segments = db.get_uptime_segments(hours=hours)
    if email:
        user_lab_ids = {lab["id"] for lab in db.get_labs_for_email(email)}
        segments = {k: v for k, v in segments.items() if k in user_lab_ids}
    return segments


@app.get("/api/v1/widgets/alerts")
def widget_alerts(request: Request, limit: int = 20):
    """Recent alert feed for dashboard widget."""
    email = _get_session_email(request)
    alerts = db.get_recent_alerts_feed(limit=limit)
    if email:
        user_lab_ids = {lab["id"] for lab in db.get_labs_for_email(email)}
        alerts = [a for a in alerts if a["lab_id"] in user_lab_ids]
    return alerts


@app.get("/api/v1/widgets/sparkline/{lab_id}/{metric}")
def widget_sparkline(lab_id: str, metric: str, hours: int = 1):
    """Sparkline data for a specific lab metric."""
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
         "alert_count": 1, "critical_count": 0,
         "last_seen": datetime.utcnow().isoformat()},
        {"id": "demo-2", "name": "docker-host", "hostname": "docker-01", "online": True,
         "cpu_percent": 8.1, "memory_percent": 38.7, "disk_percent": 29.3, "load_1m": 0.45,
         "container_count": 22, "os": "Ubuntu 24.04", "arch": "x86_64",
         "alert_count": 0, "critical_count": 0,
         "last_seen": datetime.utcnow().isoformat()},
        {"id": "demo-3", "name": "nas-storage", "hostname": "storage-01", "online": True,
         "cpu_percent": 4.2, "memory_percent": 72.8, "disk_percent": 78.1, "load_1m": 3.21,
         "container_count": 0, "os": "TrueNAS SCALE", "arch": "x86_64",
         "alert_count": 2, "critical_count": 1,
         "last_seen": datetime.utcnow().isoformat()},
        {"id": "demo-4", "name": "gpu-server", "hostname": "gpu-01", "online": False,
         "cpu_percent": 0, "memory_percent": 0, "disk_percent": 55.3, "load_1m": 0,
         "container_count": 0, "os": "Arch Linux", "arch": "x86_64",
         "alert_count": 1, "critical_count": 1,
         "last_seen": (datetime.utcnow() - timedelta(hours=3)).isoformat()},
    ]
    return templates.TemplateResponse("dashboard.html", _tpl_context(
        request, labs=demo_labs, total=len(demo_labs), secret="demo", is_demo=True,
    ))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, x_admin_secret: Optional[str] = Header(None)):
    # Also allow query param for browser access
    secret = x_admin_secret or request.query_params.get("secret")
    if secret != config.ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

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

    return templates.TemplateResponse("dashboard.html", _tpl_context(
        request, labs=lab_data, total=len(lab_data), secret=secret,
    ))


@app.get("/dashboard/lab/{lab_id}", response_class=HTMLResponse)
def dashboard_lab_detail(request: Request, lab_id: str, x_admin_secret: Optional[str] = Header(None)):
    secret = x_admin_secret or request.query_params.get("secret")
    if secret != config.ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    lab = db.get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")

    # Admin view can see up to the longest tier's retention window.
    max_retention = max(
        (t.get("retention_hours") or 0) for t in config.TIER_LIMITS.values()
    )
    history_hours = int(request.query_params.get("hours", "24"))
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

    return templates.TemplateResponse("lab_detail.html", _tpl_context(
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
    secret = x_admin_secret or request.query_params.get("secret")
    if secret != config.ADMIN_SECRET:
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
        result.append({
            **lab,
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
        lab_data.append({
            **lab,
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
            "exported_at": datetime.utcnow().isoformat(),
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


@app.delete("/api/v1/admin/lab/{lab_id}")
def admin_delete_lab(lab_id: str, _: str = Depends(_require_admin)):
    deleted = db.delete_lab(lab_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Lab not found")
    return {"status": "deleted", "lab_id": lab_id}


# ---------------------------------------------------------------------------
# Demo NLQ — canned responses for the public demo page
# ---------------------------------------------------------------------------

import re as _re

_DEMO_RESPONSES = [
    {
        "patterns": [
            r"fleet", r"summary", r"overview", r"sitrep", r"rundown",
            r"(?:fleet|overall|lab)\s+(?:status|health)",
            r"^(?:status|health)$",
            r"how(?:'s| is) (?:my |the |our )?(?:lab|fleet|cluster|everything|infra)",
            r"how(?:'s| is) everything",
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
            r"(?:top|rank|compare|sort)\s+(?:by\s+)?(?:cpu|memory|mem|disk|load)",
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
                "  proxmox-01: 12.4 Mbps rx / 8.2 Mbps tx\n"
                "  docker-01: 45.8 Mbps rx / 32.1 Mbps tx\n"
                "  storage-01: 2.1 Mbps rx / 1.8 Mbps tx\n"
                "  gpu-01: OFFLINE\n"
                "\n"
                "docker-01 has the highest throughput — likely serving container traffic."
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


def _demo_nlq_response(question: str) -> dict:
    """Return a canned NLQ response for demo mode.

    Uses simple regex pattern matching against the question to select
    the most appropriate demo response. Falls back to a helpful message
    if no pattern matches.
    """
    q = question.lower().strip().rstrip("?")

    # If the query is just a node name (possibly with "status", "health", etc.),
    # return the node-specific response directly.
    _demo_node_names = list(_DEMO_NODE_STATUS.keys())
    q_words = _re.sub(r'[^a-z0-9\s-]', '', q).split()
    _noise_words = {"status", "state", "health", "how", "is", "the", "my", "doing",
                    "check", "ok", "okay", "what", "whats", "hows", "about", "s"}
    q_meaningful = [w for w in q_words if w not in _noise_words]

    for node_name in _demo_node_names:
        if node_name.lower() in q:
            # If the only meaningful content is the node name, return status
            remaining = [w for w in q_meaningful if w != node_name.lower()]
            if not remaining or all(w in _noise_words for w in remaining):
                return _DEMO_NODE_STATUS[node_name]

    # Check general pattern-based responses (diagnostic, alerts, etc.)
    for entry in _DEMO_RESPONSES:
        for pattern in entry["patterns"]:
            if _re.search(pattern, q):
                return entry["response"]

    # Check for node-specific status queries as final catch
    # (e.g., a node name embedded in a query that didn't match patterns above)
    for node_name, response in _DEMO_NODE_STATUS.items():
        if node_name.lower() in q:
            return response

    # Fallback
    return {
        "answer": (
            "I understood your question but don't have a canned demo response for it. "
            "In production, labwatch analyzes your real fleet metrics to answer natural "
            "language questions about your infrastructure.\n"
            "\n"
            "Try asking:\n"
            "  - \"fleet status\"\n"
            "  - \"what needs attention?\"\n"
            "  - \"show me all alerts\"\n"
            "  - \"why is nas-storage slow?\"\n"
            "  - \"what containers are running?\"\n"
            "  - \"how hot is everything?\"\n"
            "  - \"which node uses the most cpu?\"\n"
            "  - \"how much disk space do I have?\""
        ),
        "query_type": "fallback",
        "confidence": 0.0,
        "demo": True,
    }


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

    question = request_body.get("question", "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="question is required")

    # Demo mode: return canned responses for the public demo page
    if secret == "demo":
        result = _demo_nlq_response(question)
        return result

    lang = detect_language(request)

    from nlq import query

    if secret == config.ADMIN_SECRET:
        return query(question, lang=lang)

    # Session-auth fallback: user dashboard widget sends an empty secret.
    email = _get_session_email(request)
    if email:
        return query(question, email=email, lang=lang)

    raise HTTPException(status_code=403, detail="Forbidden")


@app.post("/api/v1/admin/digest/{lab_id}")
def generate_lab_digest(lab_id: str, hours: int = 168, _: str = Depends(_require_admin)):
    """Generate an intelligence digest for a specific lab."""
    from digest import generate_digest
    lab = db.get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")
    return generate_digest(lab_id, lab["hostname"], hours=hours)


@app.post("/api/v1/admin/digest")
def generate_fleet_digest_endpoint(hours: int = 168, _: str = Depends(_require_admin)):
    """Generate an intelligence digest for the entire fleet."""
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
    channels = db.list_notification_channels()
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
    if channel_type not in ("webhook", "ntfy", "telegram"):
        raise HTTPException(status_code=400, detail="channel_type must be 'webhook', 'ntfy', or 'telegram'")
    if min_severity not in ("info", "warning", "critical"):
        raise HTTPException(status_code=400, detail="min_severity must be 'info', 'warning', or 'critical'")

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
            success_url=f"{config.BASE_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{config.BASE_URL}/billing/cancel",
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
        logging.getLogger("labwatch").warning(f"Stripe webhook signature rejected: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")

    logger = logging.getLogger("labwatch")
    event_type = event.get("type") if isinstance(event, dict) else event["type"]

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata") or {}
        email = metadata.get("email") or session.get("customer_email") or session.get("client_reference_id")
        plan = (metadata.get("plan") or "").lower()
        if not email:
            logger.warning(f"Stripe checkout.session.completed with no email: {session.get('id')}")
            return {"ok": True, "noop": "no email"}
        if plan not in config.TIER_LIMITS:
            # Missing/unknown metadata.plan means we'd guess — refuse to ship
            # the wrong plan. 200 so Stripe doesn't retry, but loud log.
            logger.error(f"Stripe event with missing/unknown plan {plan!r} for {email} ({session.get('id')})")
            return {"ok": True, "noop": "unknown plan"}
        rows = db.set_plan_for_email(email, plan)
        if rows == 0:
            # User paid but we couldn't find their row — worth paging on.
            logger.error(f"Stripe upgrade: {email} → {plan} matched 0 rows ({session.get('id')})")
        else:
            logger.info(f"Stripe upgrade: {email} → {plan} ({rows} rows updated)")
        # Best-effort confirmation email. mailer catches and logs its own
        # errors so a Resend outage never causes Stripe to retry. Offload to
        # a thread so the ~10s Resend timeout can't starve the event loop.
        if rows > 0:
            await asyncio.to_thread(
                mailer.send_plan_upgrade_receipt, email, plan, session.get("id", "")
            )
        return {"ok": True, "email": email, "plan": plan, "rows": rows}

    if event_type == "customer.subscription.deleted":
        # Downgrade to free on cancellation. Stripe's `customer_email` isn't
        # on subscription events, so we rely on metadata set at checkout time.
        sub = event["data"]["object"]
        metadata = sub.get("metadata") or {}
        email = metadata.get("email")
        if email:
            rows = db.set_plan_for_email(email, config.DEFAULT_PLAN)
            logger.info(f"Stripe cancellation: {email} → {config.DEFAULT_PLAN} ({rows} rows)")
            if rows > 0:
                await asyncio.to_thread(mailer.send_plan_downgrade_notice, email)
            return {"ok": True, "email": email, "plan": config.DEFAULT_PLAN, "rows": rows}

    # Unhandled event types are acknowledged with 200 so Stripe doesn't retry.
    return {"ok": True, "event": event_type}


@app.get("/billing/success", response_class=HTMLResponse)
def billing_success(request: Request):
    """Landing page after a successful checkout redirect. The actual plan
    flip happens in the webhook — this page just thanks the user and
    points them at their dashboard.
    """
    return templates.TemplateResponse("billing_result.html", _tpl_context(
        request, outcome="success",
    ))


@app.get("/billing/cancel", response_class=HTMLResponse)
def billing_cancel(request: Request):
    """Landing page if the user cancels/closes the checkout page."""
    return templates.TemplateResponse("billing_result.html", _tpl_context(
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
        reload=True,
    )
