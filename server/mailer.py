"""Transactional email via Resend.

Only two events currently need email: a plan upgrade (receipt/confirmation)
and a plan downgrade (Stripe subscription ended). Everything is triggered
from the billing webhook, so failures here must not blow up the webhook
response — Stripe would retry indefinitely. We log and swallow.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Optional

import config

logger = logging.getLogger("labwatch.mailer")

_RESEND_URL = "https://api.resend.com/emails"
_TIMEOUT = 10.0


def _send(to: str, subject: str, html: str, text: str) -> Optional[str]:
    """POST to Resend. Returns message id on success, None on failure.
    Silent no-op when EMAIL_ENABLED is False (dev / unconfigured box).
    """
    if not config.EMAIL_ENABLED:
        logger.info(f"skipping send to {to} (EMAIL_ENABLED=False)")
        return None
    payload = json.dumps({
        "from": config.EMAIL_FROM,
        "to": [to],
        "subject": subject,
        "html": html,
        "text": text,
        "reply_to": config.EMAIL_REPLY_TO,
    }).encode("utf-8")
    req = urllib.request.Request(
        _RESEND_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {config.RESEND_API_KEY}",
            "Content-Type": "application/json",
            # Resend sits behind Cloudflare and blocks the default
            # "Python-urllib/..." UA (1010 error).
            "User-Agent": "labwatch-server/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        msg_id = body.get("id")
        logger.info(f"sent {subject!r} to {to} (resend_id={msg_id})")
        return msg_id
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        logger.warning(f"resend returned {e.code} for {to}: {detail}")
        return None
    except Exception as e:
        logger.warning(f"send to {to} failed: {e}")
        return None


def _wrap_email(title: str, title_color: str, body_html: str, cta_url: str,
                cta_label: str, cta_style: str, footer_html: str = "") -> str:
    """Render the shared dark-themed email shell around per-message content."""
    return f"""<!doctype html>
<html>
<body style="font-family: -apple-system, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e5e5e5; margin: 0; padding: 40px 20px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="max-width: 560px; background: #141414; border: 1px solid #2a2a2a; border-radius: 12px; padding: 40px 32px;">
        <tr><td>
          <h1 style="font-size: 22px; margin: 0 0 16px 0; color: {title_color};">{title}</h1>
          {body_html}
          <p style="margin: 24px 0;">
            <a href="{cta_url}" style="display: inline-block; {cta_style} padding: 10px 22px; border-radius: 6px; font-weight: 600; text-decoration: none;">{cta_label}</a>
          </p>
          {footer_html}
          <p style="font-size: 13px; color: #666; margin: 32px 0 0 0;">— the labwatch team</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def send_plan_upgrade_receipt(email: str, plan: str, session_id: str = "") -> Optional[str]:
    """Confirm a plan upgrade after the Stripe webhook flips the row."""
    plan_display = plan.capitalize()
    subject = f"Welcome to labwatch {plan_display}"
    base_url = config.BASE_URL.rstrip("/")
    dashboard_url = f"{base_url}/my/dashboard"

    text = (
        f"Hi,\n\n"
        f"Your labwatch plan is now {plan_display}. The new limits are active "
        f"immediately — head to your dashboard to see everything unlocked:\n\n"
        f"{dashboard_url}\n\n"
        f"Stripe handles the billing side, so you'll get a separate receipt "
        f"from them for the charge itself. If anything looks wrong or you "
        f"have questions, just reply to this email.\n\n"
        f"Thanks for supporting labwatch.\n"
        f"— the labwatch team"
    )
    if session_id:
        text += f"\n\n(ref: {session_id})"

    body_html = (
        f'<p style="font-size: 15px; line-height: 1.6; color: #cccccc; margin: 0 0 16px 0;">'
        f'Your plan is now <strong>{plan_display}</strong>. The new limits are active '
        f'immediately — head to your dashboard to see everything unlocked.</p>'
    )
    footer_html = (
        '<p style="font-size: 14px; line-height: 1.6; color: #888; margin: 24px 0 0 0;">'
        "Stripe handles the billing side, so you'll get a separate receipt from them "
        "for the charge itself. If anything looks wrong or you have questions, just "
        "reply to this email.</p>"
    )
    if session_id:
        footer_html += f'<p style="font-size: 11px; color: #444; margin: 16px 0 0 0;">ref: {session_id}</p>'

    html = _wrap_email(
        title=f"Welcome to labwatch {plan_display}",
        title_color="#f4c430",
        body_html=body_html,
        cta_url=dashboard_url,
        cta_label="Open dashboard",
        cta_style="background: #f4c430; color: #000;",
        footer_html=footer_html,
    )

    return _send(email, subject, html, text)


def send_plan_downgrade_notice(email: str) -> Optional[str]:
    """Notify a user that their subscription ended and they're back on the free plan."""
    plan_display = config.DEFAULT_PLAN.capitalize()
    subject = "Your labwatch subscription has ended"
    base_url = config.BASE_URL.rstrip("/")
    pricing_url = f"{base_url}/#pricing"

    text = (
        f"Hi,\n\n"
        f"Stripe just told us your subscription has ended, so your labwatch "
        f"plan is back on {plan_display}. Your data is still here and your "
        f"nodes keep working — the only change is that the Pro retention "
        f"window and node cap revert to the {plan_display} defaults.\n\n"
        f"If this was a mistake or you'd like to resubscribe, you can pick "
        f"a plan here:\n\n{pricing_url}\n\n"
        f"If you cancelled on purpose — thanks for trying labwatch, and "
        f"reply to this email if there's anything we could have done "
        f"better.\n\n— the labwatch team"
    )

    body_html = (
        f'<p style="font-size: 15px; line-height: 1.6; color: #cccccc; margin: 0 0 16px 0;">'
        f'Stripe just told us your subscription has ended, so your labwatch plan is back '
        f'on <strong>{plan_display}</strong>. Your data is still here and your nodes keep '
        f'working — the only change is that the Pro retention window and node cap revert '
        f'to the {plan_display} defaults.</p>'
    )
    footer_html = (
        '<p style="font-size: 14px; line-height: 1.6; color: #888; margin: 24px 0 0 0;">'
        "If you cancelled on purpose — thanks for trying labwatch, and reply to this "
        "email if there's anything we could have done better.</p>"
    )

    html = _wrap_email(
        title="Your labwatch subscription has ended",
        title_color="#e5e5e5",
        body_html=body_html,
        cta_url=pricing_url,
        cta_label="See plans",
        cta_style="background: transparent; border: 1px solid #f4c430; color: #f4c430;",
        footer_html=footer_html,
    )

    return _send(email, subject, html, text)
