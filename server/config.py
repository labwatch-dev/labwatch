"""Configuration for Homelab Intelligence (labwatch) server."""

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _require_env(key: str) -> str:
    val = os.getenv(key)
    if not val:
        raise RuntimeError(f"Required environment variable {key} is not set")
    return val


def _read_secret_file(path: str) -> str:
    """Read a single-line secret from disk, or return empty string if missing.
    Using files instead of env vars keeps credentials out of process listings
    and the .env file, matching the pattern of other services on the box.
    """
    try:
        return Path(path).expanduser().read_text(encoding="utf-8").strip()
    except (FileNotFoundError, PermissionError):
        return ""


def _read_kv_file(path: str) -> dict[str, str]:
    """Parse a simple KEY=VALUE file (one per line) into a dict."""
    out: dict[str, str] = {}
    try:
        for line in Path(path).expanduser().read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    except (FileNotFoundError, PermissionError):
        pass
    return out


ADMIN_SECRET: str = _require_env("ADMIN_SECRET")
SESSION_SECRET: str = os.getenv("SESSION_SECRET", secrets.token_hex(32))  # for signing cookies; auto-generated if not set
DATABASE_PATH: str = os.getenv("DATABASE_PATH", "./data/labwatch.db")
HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8097"))
BASE_URL: str = os.getenv("BASE_URL", "http://localhost:8097")

# Legacy fallback retention used by admin-only routes that aren't scoped to a
# specific user. Tier-aware enforcement (the common path) uses TIER_LIMITS below.
RETENTION_HOURS: int = int(os.getenv("RETENTION_HOURS", "168"))

# Plan definitions. Must stay in sync with /#pricing marketing copy.
#   node_cap:        max registered nodes per email (None = unlimited)
#   retention_hours: metric history window enforced by the periodic purge
DEFAULT_PLAN: str = "free"
TIER_LIMITS: dict[str, dict] = {
    "free":     {"node_cap": 3,    "retention_hours": 30 * 24},
    "pro":      {"node_cap": None, "retention_hours": 365 * 24},
    "business": {"node_cap": None, "retention_hours": 365 * 24},
}

# Stripe credentials — read at startup from ~/.config/stripe/. Empty strings
# mean billing is disabled (endpoints return 503). The checkout + webhook
# routes re-check these so a missing-key install is a clean failure, not a
# crash at startup.
STRIPE_SECRET_KEY: str = _read_secret_file("~/.config/stripe/secret_key")
STRIPE_WEBHOOK_SECRET: str = _read_secret_file("~/.config/stripe/webhook_secret")
_STRIPE_PRICE_IDS: dict[str, str] = _read_kv_file("~/.config/stripe/price_ids")

# Map plan name → Stripe price ID. Only plans with a configured price ID are
# considered purchasable; others cannot be upgraded to via checkout.
STRIPE_PRICE_BY_PLAN: dict[str, str] = {
    "pro":      _STRIPE_PRICE_IDS.get("STRIPE_PRICE_PRO", ""),
    "business": _STRIPE_PRICE_IDS.get("STRIPE_PRICE_BUSINESS", ""),
}

BILLING_ENABLED: bool = bool(
    STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET and STRIPE_PRICE_BY_PLAN.get("pro")
)

# Resend transactional email. The domain labwatch.dev is verified in the
# Resend dashboard so we can send from any @labwatch.dev address. Missing
# key → EMAIL_ENABLED is False and mailer.send() becomes a no-op so the
# rest of the request path stays unaffected on dev boxes.
RESEND_API_KEY: str = _read_secret_file("~/.config/resend/api_key")
EMAIL_FROM: str = os.getenv("EMAIL_FROM", "labwatch <billing@labwatch.dev>")
EMAIL_REPLY_TO: str = os.getenv("EMAIL_REPLY_TO", "support@labwatch.dev")
EMAIL_ENABLED: bool = bool(RESEND_API_KEY)
