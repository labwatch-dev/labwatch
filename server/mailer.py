"""Transactional email via Resend.

Only two events currently need email: a plan upgrade (receipt/confirmation)
and a plan downgrade (Stripe subscription ended). Everything is triggered
from the billing webhook, so failures here must not blow up the webhook
response — Stripe would retry indefinitely. We log and swallow.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

import config

logger = logging.getLogger(__name__)

_RESEND_URL = "https://api.resend.com/emails"
_TIMEOUT = 10.0


def _send(to: str, subject: str, html: str, text: str) -> Optional[str]:
    """POST to Resend. Returns message id on success, None on failure.
    Silent no-op when EMAIL_ENABLED is False (dev / unconfigured box).
    """
    if not config.EMAIL_ENABLED:
        logger.info(f"mailer: skipping send to {to} (EMAIL_ENABLED=False)")
        return None
    payload = {
        "from": config.EMAIL_FROM,
        "to": [to],
        "subject": subject,
        "html": html,
        "text": text,
        "reply_to": config.EMAIL_REPLY_TO,
    }
    headers = {
        "Authorization": f"Bearer {config.RESEND_API_KEY}",
        "Content-Type": "application/json",
    }
    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.post(_RESEND_URL, json=payload, headers=headers)
        if resp.status_code >= 300:
            logger.warning(
                f"mailer: resend returned {resp.status_code} for {to}: {resp.text[:500]}"
            )
            return None
        msg_id = resp.json().get("id")
        logger.info(f"mailer: sent {subject!r} to {to} (resend_id={msg_id})")
        return msg_id
    except Exception as e:
        logger.warning(f"mailer: send to {to} failed: {e}")
        return None


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

    html = f"""<!doctype html>
<html>
<body style="font-family: -apple-system, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e5e5e5; margin: 0; padding: 40px 20px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="max-width: 560px; background: #141414; border: 1px solid #2a2a2a; border-radius: 12px; padding: 40px 32px;">
        <tr><td>
          <h1 style="font-size: 22px; margin: 0 0 16px 0; color: #f4c430;">Welcome to labwatch {plan_display}</h1>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc; margin: 0 0 16px 0;">
            Your plan is now <strong>{plan_display}</strong>. The new limits are active immediately — head to your dashboard to see everything unlocked.
          </p>
          <p style="margin: 24px 0;">
            <a href="{dashboard_url}" style="display: inline-block; background: #f4c430; color: #000; padding: 10px 22px; border-radius: 6px; font-weight: 600; text-decoration: none;">Open dashboard</a>
          </p>
          <p style="font-size: 14px; line-height: 1.6; color: #888; margin: 24px 0 0 0;">
            Stripe handles the billing side, so you'll get a separate receipt from them for the charge itself. If anything looks wrong or you have questions, just reply to this email.
          </p>
          <p style="font-size: 13px; color: #666; margin: 32px 0 0 0;">— the labwatch team</p>
          {f'<p style="font-size: 11px; color: #444; margin: 16px 0 0 0;">ref: {session_id}</p>' if session_id else ''}
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    return _send(email, subject, html, text)


def send_plan_downgrade_notice(email: str, plan: str) -> Optional[str]:
    """Notify a user that their subscription ended and they're back on the free plan."""
    plan_display = plan.capitalize()
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

    html = f"""<!doctype html>
<html>
<body style="font-family: -apple-system, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e5e5e5; margin: 0; padding: 40px 20px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="max-width: 560px; background: #141414; border: 1px solid #2a2a2a; border-radius: 12px; padding: 40px 32px;">
        <tr><td>
          <h1 style="font-size: 22px; margin: 0 0 16px 0; color: #e5e5e5;">Your labwatch subscription has ended</h1>
          <p style="font-size: 15px; line-height: 1.6; color: #cccccc; margin: 0 0 16px 0;">
            Stripe just told us your subscription has ended, so your labwatch plan is back on <strong>{plan_display}</strong>. Your data is still here and your nodes keep working — the only change is that the Pro retention window and node cap revert to the {plan_display} defaults.
          </p>
          <p style="margin: 24px 0;">
            <a href="{pricing_url}" style="display: inline-block; background: transparent; border: 1px solid #f4c430; color: #f4c430; padding: 10px 22px; border-radius: 6px; font-weight: 600; text-decoration: none;">See plans</a>
          </p>
          <p style="font-size: 14px; line-height: 1.6; color: #888; margin: 24px 0 0 0;">
            If you cancelled on purpose — thanks for trying labwatch, and reply to this email if there's anything we could have done better.
          </p>
          <p style="font-size: 13px; color: #666; margin: 32px 0 0 0;">— the labwatch team</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    return _send(email, subject, html, text)
