"""Alert notification dispatcher for labwatch."""

import html
import json
import logging
import urllib.request
import urllib.error
from typing import Any
from urllib.parse import urlparse

import database as db


def _validate_url(url: str) -> None:
    """Reject URLs with dangerous schemes (file://, ftp://) or missing host."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL scheme must be http or https, got '{parsed.scheme}'")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")

logger = logging.getLogger("labwatch.notifications")

# Severity ordering for filtering
SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


def should_notify(channel_min_severity: str, alert_severity: str) -> bool:
    """Check if alert severity meets channel minimum threshold."""
    return SEVERITY_ORDER.get(alert_severity, 0) >= SEVERITY_ORDER.get(channel_min_severity, 0)


def send_alert_notification(alert: dict, lab: dict) -> list[dict]:
    """Send notification for a new alert to all enabled channels.

    Fires BOTH global admin channels AND the lab owner's per-user channels.

    Args:
        alert: dict with keys: type, severity, message, data
        lab: dict with keys: id, hostname

    Returns:
        list of result dicts: [{channel_id, channel_name, success, error, scope}]
    """
    results = []

    # --- Global (admin) channels ---
    for ch in db.list_notification_channels():
        if not ch.get("enabled"):
            continue
        if not should_notify(ch.get("min_severity", "warning"), alert["severity"]):
            continue

        config = ch.get("config", {})
        if isinstance(config, str):
            config = json.loads(config)

        try:
            sender = CHANNEL_SENDERS.get(ch["channel_type"])
            if sender is None:
                raise ValueError(f"Unknown channel type: {ch['channel_type']}")
            sender(ch, alert, lab, config)
            results.append({
                "channel_id": ch["id"], "channel_name": ch["name"],
                "success": True, "scope": "admin",
            })
            logger.info(
                f"Notification sent via {ch['channel_type']} channel '{ch['name']}' "
                f"for alert {alert['type']} on {lab.get('hostname', 'unknown')}"
            )
        except Exception as e:
            results.append({
                "channel_id": ch["id"], "channel_name": ch["name"],
                "success": False, "error": str(e), "scope": "admin",
            })
            logger.error(
                f"Failed to send notification via {ch['channel_type']} channel "
                f"'{ch['name']}': {e}"
            )

    # --- Per-user channels for the lab owner ---
    lab_id = lab.get("id")
    if lab_id:
        try:
            owner_email = db.get_email_for_lab(lab_id)
        except Exception:
            owner_email = None
        if owner_email:
            try:
                raw = db._get_pref(owner_email, "notification_channels", None) or {}
                user_channels = raw.get("channels", []) if isinstance(raw, dict) else []
            except Exception:
                user_channels = []

            for uch in user_channels:
                if not uch.get("enabled", True):
                    continue
                if not should_notify(uch.get("min_severity", "warning"), alert["severity"]):
                    continue
                ctype = uch.get("type")
                config = uch.get("config", {}) or {}
                try:
                    sender = CHANNEL_SENDERS.get(ctype)
                    if sender is None:
                        raise ValueError(f"Unknown channel type: {ctype}")
                    sender(
                        {"name": uch.get("name", ""), "channel_type": ctype},
                        alert, lab, config,
                    )
                    results.append({
                        "channel_id": uch.get("id"), "channel_name": uch.get("name"),
                        "success": True, "scope": "user",
                    })
                    logger.info(
                        f"User notification sent via {ctype} channel '{uch.get('name')}' "
                        f"({owner_email}) for alert {alert['type']} on {lab.get('hostname', 'unknown')}"
                    )
                except Exception as e:
                    results.append({
                        "channel_id": uch.get("id"), "channel_name": uch.get("name"),
                        "success": False, "error": str(e), "scope": "user",
                    })
                    logger.error(
                        f"Failed to send user notification via {ctype} channel "
                        f"'{uch.get('name')}' ({owner_email}): {e}"
                    )

    return results


def _send_webhook(channel: dict, alert: dict, lab: dict, config: dict) -> None:
    """Send alert via generic webhook (POST JSON)."""
    url = config.get("url")
    if not url:
        raise ValueError("Webhook URL not configured")
    _validate_url(url)

    payload = {
        "event": "alert",
        "lab_id": lab.get("id"),
        "hostname": lab.get("hostname"),
        "alert_type": alert["type"],
        "severity": alert["severity"],
        "message": alert["message"],
        "data": alert.get("data", {}),
    }

    headers = {"Content-Type": "application/json"}
    # Support optional auth header
    if config.get("auth_header"):
        header_name, header_value = config["auth_header"].split(":", 1)
        headers[header_name.strip()] = header_value.strip()

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Webhook returned HTTP {resp.status}")


def _send_ntfy(channel: dict, alert: dict, lab: dict, config: dict) -> None:
    """Send alert via ntfy (https://ntfy.sh or self-hosted)."""
    server = config.get("server", "https://ntfy.sh")
    topic = config.get("topic")
    if not topic:
        raise ValueError("ntfy topic not configured")

    url = f"{server.rstrip('/')}/{topic}"
    _validate_url(url)

    # Map severity to ntfy priority
    priority_map = {"info": "low", "warning": "default", "critical": "urgent"}
    priority = priority_map.get(alert["severity"], "default")

    # Map severity to emoji tags
    tag_map = {"info": "information_source", "warning": "warning", "critical": "rotating_light"}
    tags = tag_map.get(alert["severity"], "bell")

    hostname = lab.get("hostname", "unknown")
    title = f"[{alert['severity'].upper()}] {hostname}"
    body = alert["message"]

    headers = {
        "Title": title,
        "Priority": priority,
        "Tags": tags,
    }

    # Optional ntfy auth token
    if config.get("token"):
        headers["Authorization"] = f"Bearer {config['token']}"

    req = urllib.request.Request(url, data=body.encode("utf-8"), headers=headers, method="POST")

    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"ntfy returned HTTP {resp.status}")


def _send_telegram(channel: dict, alert: dict, lab: dict, config: dict) -> None:
    """Send alert via Telegram Bot API."""
    bot_token = config.get("bot_token")
    chat_id = config.get("chat_id")
    if not bot_token:
        raise ValueError("Telegram bot_token not configured")
    if not chat_id:
        raise ValueError("Telegram chat_id not configured")

    # Map severity to emoji
    emoji_map = {
        "info": "\u2139\ufe0f",       # information source
        "warning": "\u26a0\ufe0f",     # warning
        "critical": "\U0001f6a8",      # rotating light
    }
    emoji = emoji_map.get(alert["severity"], "\U0001f514")  # bell fallback

    hostname = lab.get("hostname", "unknown")
    severity_label = alert["severity"].upper()

    text = (
        f"{emoji} <b>{severity_label} Alert</b>\n"
        f"\n"
        f"<b>Host:</b> {html.escape(hostname)}\n"
        f"<b>Type:</b> {html.escape(alert['type'])}\n"
        f"<b>Message:</b> {html.escape(alert['message'])}"
    )

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")

    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Telegram API returned HTTP {resp.status}")
        # Check Telegram's ok field in response
        body = json.loads(resp.read().decode("utf-8"))
        if not body.get("ok"):
            raise RuntimeError(f"Telegram API error: {body.get('description', 'unknown error')}")


def _send_discord(channel: dict, alert: dict, lab: dict, config: dict) -> None:
    """Send alert via Discord webhook."""
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        raise ValueError("Discord webhook_url not configured")
    _validate_url(webhook_url)

    color_map = {"info": 0x3498db, "warning": 0xf39c12, "critical": 0xe74c3c}
    color = color_map.get(alert["severity"], 0x95a5a6)
    hostname = lab.get("hostname", "unknown")

    payload = {
        "username": config.get("username", "labwatch"),
        "embeds": [{
            "title": f"[{alert['severity'].upper()}] {hostname}",
            "description": alert["message"],
            "color": color,
            "fields": [
                {"name": "Type", "value": alert["type"], "inline": True},
                {"name": "Host", "value": hostname, "inline": True},
            ],
            "footer": {"text": "labwatch"},
        }],
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Discord webhook returned HTTP {resp.status}")


def _send_slack(channel: dict, alert: dict, lab: dict, config: dict) -> None:
    """Send alert via Slack incoming webhook."""
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        raise ValueError("Slack webhook_url not configured")
    _validate_url(webhook_url)

    color_map = {"info": "#3498db", "warning": "warning", "critical": "danger"}
    color = color_map.get(alert["severity"], "#95a5a6")
    hostname = lab.get("hostname", "unknown")

    payload = {
        "attachments": [{
            "color": color,
            "title": f"[{alert['severity'].upper()}] {hostname}",
            "text": alert["message"],
            "fields": [
                {"title": "Type", "value": alert["type"], "short": True},
                {"title": "Host", "value": hostname, "short": True},
            ],
            "footer": "labwatch",
        }],
    }
    if config.get("channel"):
        payload["channel"] = config["channel"]
    if config.get("username"):
        payload["username"] = config["username"]

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Slack webhook returned HTTP {resp.status}")


def _send_gotify(channel: dict, alert: dict, lab: dict, config: dict) -> None:
    """Send alert via Gotify (self-hosted push)."""
    server = config.get("server")
    token = config.get("token")
    if not server:
        raise ValueError("Gotify server not configured")
    if not token:
        raise ValueError("Gotify token not configured")

    # Gotify priority: 0-10, map severity roughly
    priority_map = {"info": 3, "warning": 6, "critical": 9}
    priority = priority_map.get(alert["severity"], 5)
    hostname = lab.get("hostname", "unknown")

    _validate_url(server)
    url = f"{server.rstrip('/')}/message?token={token}"
    payload = {
        "title": f"[{alert['severity'].upper()}] {hostname}",
        "message": alert["message"],
        "priority": priority,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Gotify returned HTTP {resp.status}")


def _send_pushover(channel: dict, alert: dict, lab: dict, config: dict) -> None:
    """Send alert via Pushover."""
    user_key = config.get("user_key")
    api_token = config.get("api_token")
    if not user_key:
        raise ValueError("Pushover user_key not configured")
    if not api_token:
        raise ValueError("Pushover api_token not configured")

    # Pushover priority: -2..2
    priority_map = {"info": -1, "warning": 0, "critical": 1}
    priority = priority_map.get(alert["severity"], 0)
    hostname = lab.get("hostname", "unknown")

    import urllib.parse
    body = urllib.parse.urlencode({
        "token": api_token,
        "user": user_key,
        "title": f"[{alert['severity'].upper()}] {hostname}",
        "message": alert["message"],
        "priority": priority,
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.pushover.net/1/messages.json", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"Pushover returned HTTP {resp.status}")
        result = json.loads(resp.read().decode("utf-8"))
        if result.get("status") != 1:
            raise RuntimeError(f"Pushover error: {result.get('errors', 'unknown')}")


def _send_apprise(channel: dict, alert: dict, lab: dict, config: dict) -> None:
    """Send alert via Apprise — wraps 100+ notification services.

    Config: {"url": "tgram://bottoken/chatid"}  or any Apprise URL.
    See https://github.com/caronc/apprise/wiki for URL formats.
    """
    url = config.get("url")
    if not url:
        raise ValueError("Apprise URL not configured")

    try:
        import apprise  # local import — only loaded when Apprise channel is used
    except ImportError:
        raise RuntimeError("Apprise not installed (pip install apprise)")

    apobj = apprise.Apprise()
    if not apobj.add(url):
        raise ValueError(f"Invalid Apprise URL: {url[:40]}...")

    severity_map = {
        "info": apprise.NotifyType.INFO,
        "warning": apprise.NotifyType.WARNING,
        "critical": apprise.NotifyType.FAILURE,
    }
    ntype = severity_map.get(alert["severity"], apprise.NotifyType.INFO)
    hostname = lab.get("hostname", "unknown")
    sev = alert["severity"].upper()
    title = f"[{sev}] {hostname}"
    body = alert["message"]

    ok = apobj.notify(body=body, title=title, notify_type=ntype)
    if not ok:
        raise RuntimeError("Apprise notification failed (check URL and service)")

# Registry: channel_type -> sender function
CHANNEL_SENDERS = {
    "webhook": _send_webhook,
    "ntfy": _send_ntfy,
    "telegram": _send_telegram,
    "discord": _send_discord,
    "slack": _send_slack,
    "gotify": _send_gotify,
    "pushover": _send_pushover,
    "apprise": _send_apprise,
}


def send_to_channel(channel_type: str, config: dict, alert: dict, lab: dict) -> None:
    """Dispatch an alert to a channel by type. Raises on failure."""
    sender = CHANNEL_SENDERS.get(channel_type)
    if not sender:
        raise ValueError(f"Unknown channel type: {channel_type}")
    # Sender expects a channel dict; pass minimal stub
    sender({"name": "test", "channel_type": channel_type}, alert, lab, config)


def send_test_notification(channel_id: int) -> dict:
    """Send a test notification to verify channel configuration."""
    ch = db.get_notification_channel(channel_id)
    if not ch:
        return {"success": False, "error": "Channel not found"}

    test_alert = {
        "type": "test",
        "severity": "info",
        "message": "This is a test notification from labwatch.",
        "data": {},
    }
    test_lab = {
        "id": "test",
        "hostname": "labwatch-test",
    }

    config = ch.get("config", {})
    if isinstance(config, str):
        config = json.loads(config)

    try:
        sender = CHANNEL_SENDERS.get(ch["channel_type"])
        if sender is None:
            return {"success": False, "error": f"Unknown channel type: {ch['channel_type']}", "channel": ch["name"]}
        sender(ch, test_alert, test_lab, config)
        return {"success": True, "channel": ch["name"]}
    except Exception as e:
        return {"success": False, "error": str(e), "channel": ch["name"]}
