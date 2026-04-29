"""SQLite database layer for labwatch."""

import hashlib
import json
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from config import DATABASE_PATH

logger = logging.getLogger("labwatch.database")

# Schema version — increment when adding migrations
SCHEMA_VERSION = 1


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-8000")  # 8 MB
    return conn


def init_db() -> None:
    """Create tables and data directory if they don't exist."""
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)

    conn = _connect()
    try:
        # Schema version tracking
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version     INTEGER NOT NULL,
                applied_at  TEXT NOT NULL
            )
        """)
        conn.commit()

        conn.executescript("""
            CREATE TABLE IF NOT EXISTS labs (
                id          TEXT PRIMARY KEY,
                hostname    TEXT NOT NULL,
                os          TEXT NOT NULL,
                arch        TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                token       TEXT NOT NULL UNIQUE,
                registered_at TEXT NOT NULL,
                last_seen   TEXT,
                metadata    TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS metrics (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                lab_id      TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
                timestamp   TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                data        TEXT NOT NULL,
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                lab_id      TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
                alert_type  TEXT NOT NULL,
                severity    TEXT NOT NULL CHECK(severity IN ('info', 'warning', 'critical')),
                message     TEXT NOT NULL,
                data        TEXT DEFAULT '{}',
                created_at  TEXT NOT NULL,
                resolved_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_metrics_lab_id ON metrics(lab_id);
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp);
            CREATE INDEX IF NOT EXISTS idx_metrics_lab_type ON metrics(lab_id, metric_type);
            CREATE INDEX IF NOT EXISTS idx_metrics_lab_type_ts ON metrics(lab_id, metric_type, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_lab_id ON alerts(lab_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_lab_type ON alerts(lab_id, alert_type, resolved_at);
            CREATE INDEX IF NOT EXISTS idx_labs_token ON labs(token);

            CREATE TABLE IF NOT EXISTS digests (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                lab_id      TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
                period_start TEXT NOT NULL,
                period_end  TEXT NOT NULL,
                summary     TEXT NOT NULL,
                data        TEXT DEFAULT '{}',
                created_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_digests_lab_id ON digests(lab_id);

            CREATE TABLE IF NOT EXISTS notification_channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                channel_type TEXT NOT NULL CHECK(channel_type IN ('webhook', 'ntfy', 'telegram', 'discord', 'slack', 'gotify', 'pushover', 'apprise')),
                config TEXT NOT NULL DEFAULT '{}',
                enabled INTEGER NOT NULL DEFAULT 1,
                min_severity TEXT NOT NULL DEFAULT 'warning' CHECK(min_severity IN ('info', 'warning', 'critical')),
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_notif_channels_type ON notification_channels(channel_type);

            CREATE TABLE IF NOT EXISTS signups (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                email       TEXT NOT NULL,
                password_hash TEXT,
                lab_id      TEXT REFERENCES labs(id) ON DELETE SET NULL,
                plan        TEXT NOT NULL DEFAULT 'free',
                ip_address  TEXT,
                created_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_signups_email ON signups(email);
            CREATE INDEX IF NOT EXISTS idx_signups_lab_id ON signups(lab_id);
            CREATE INDEX IF NOT EXISTS idx_signups_ip ON signups(ip_address, created_at);

            CREATE TABLE IF NOT EXISTS stripe_events (
                event_id    TEXT PRIMARY KEY,
                processed_at TEXT NOT NULL
            );
        """)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS nlq_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                question    TEXT NOT NULL,
                query_type  TEXT NOT NULL,
                matched     INTEGER NOT NULL DEFAULT 0,
                confidence  REAL NOT NULL DEFAULT 0.0,
                email       TEXT,
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ember_claims (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                email       TEXT NOT NULL,
                found_via   TEXT NOT NULL DEFAULT 'direct',
                claimed_at  TEXT NOT NULL
            );
        """)
        conn.commit()

        # Migrate notification_channels if the CHECK constraint is outdated
        # (e.g., missing 'telegram'). Detect by inspecting the table DDL.
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='notification_channels'"
        ).fetchone()
        if row:
            ddl = row[0] or ""
            if "'apprise'" not in ddl and "notification_channels" in ddl:
                logger.info("Migrating notification_channels table to support all 8 channel types")
                conn.executescript("""
                    ALTER TABLE notification_channels RENAME TO _notification_channels_old;

                    CREATE TABLE notification_channels (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        channel_type TEXT NOT NULL CHECK(channel_type IN ('webhook', 'ntfy', 'telegram', 'discord', 'slack', 'gotify', 'pushover', 'apprise')),
                        config TEXT NOT NULL DEFAULT '{}',
                        enabled INTEGER NOT NULL DEFAULT 1,
                        min_severity TEXT NOT NULL DEFAULT 'warning' CHECK(min_severity IN ('info', 'warning', 'critical')),
                        created_at TEXT NOT NULL
                    );

                    INSERT INTO notification_channels (id, name, channel_type, config, enabled, min_severity, created_at)
                        SELECT id, name, channel_type, config, enabled, min_severity, created_at
                        FROM _notification_channels_old;

                    DROP TABLE _notification_channels_old;

                    CREATE INDEX IF NOT EXISTS idx_notif_channels_type ON notification_channels(channel_type);
                """)
                conn.commit()
                logger.info("Migration complete: notification_channels now supports all 8 channel types")

        # Migrate notification_channels: add owner_email for per-user channels
        notif_cols = [r[1] for r in conn.execute("PRAGMA table_info(notification_channels)").fetchall()]
        if "owner_email" not in notif_cols:
            logger.info("Migrating notification_channels: adding owner_email column")
            conn.execute("ALTER TABLE notification_channels ADD COLUMN owner_email TEXT")
            conn.commit()

        # Migrate signups table to add password_hash column if missing
        cols = [r[1] for r in conn.execute("PRAGMA table_info(signups)").fetchall()]
        if "password_hash" not in cols:
            logger.info("Migrating signups table: adding password_hash column")
            conn.execute("ALTER TABLE signups ADD COLUMN password_hash TEXT")
            conn.commit()

        # Migrate signups: drop UNIQUE constraint on email (allows multi-node accounts)
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='signups'"
        ).fetchone()
        if row and "UNIQUE" in (row[0] or ""):
            logger.info("Migrating signups table: removing UNIQUE constraint on email")
            conn.executescript("""
                ALTER TABLE signups RENAME TO _signups_old;

                CREATE TABLE signups (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    email       TEXT NOT NULL,
                    password_hash TEXT,
                    lab_id      TEXT REFERENCES labs(id) ON DELETE SET NULL,
                    plan        TEXT NOT NULL DEFAULT 'free',
                    ip_address  TEXT,
                    created_at  TEXT NOT NULL
                );

                INSERT INTO signups (id, email, password_hash, lab_id, plan, ip_address, created_at)
                    SELECT id, email, password_hash, lab_id, plan, ip_address, created_at
                    FROM _signups_old;

                DROP TABLE _signups_old;

                CREATE INDEX IF NOT EXISTS idx_signups_email ON signups(email);
            """)
            conn.commit()
            logger.info("Migration complete: signups.email no longer UNIQUE")

        # User preferences table (pins, thresholds, notification prefs)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS user_preferences (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                email       TEXT NOT NULL,
                pref_type   TEXT NOT NULL,
                lab_id      TEXT,
                data        TEXT NOT NULL DEFAULT '{}',
                updated_at  TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_user_prefs_unique
                ON user_preferences(email, pref_type, COALESCE(lab_id, ''));
            CREATE INDEX IF NOT EXISTS idx_user_prefs_email
                ON user_preferences(email);
            CREATE INDEX IF NOT EXISTS idx_metrics_created_at ON metrics(created_at);
            CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
        """)
        conn.commit()

        # Stamp current schema version if not yet recorded
        row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        current = row[0] if row and row[0] else 0
        if current < SCHEMA_VERSION:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, now),
            )
            conn.commit()
            logger.info("Schema version set to %d", SCHEMA_VERSION)
    finally:
        conn.close()


def get_schema_version() -> int:
    """Return the current schema version, or 0 if not yet tracked."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        ).fetchone()
        if not row:
            return 0
        row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return row[0] if row and row[0] else 0
    finally:
        conn.close()


def register_lab(hostname: str, os_name: str, arch: str, version: str) -> tuple[str, str]:
    """Register a new lab agent. Returns (lab_id, token)."""
    lab_id = str(uuid4())
    token = secrets.token_hex(32)
    now = datetime.now(timezone.utc).isoformat()

    conn = _connect()
    try:
        conn.execute(
            """INSERT INTO labs (id, hostname, os, arch, agent_version, token, registered_at, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (lab_id, hostname, os_name, arch, version, token, now, now),
        )
        conn.commit()
    finally:
        conn.close()

    return lab_id, token


def _hash_password(password: str) -> str:
    """Hash a password with PBKDF2-SHA256 and a random salt."""
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"{salt}${h.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored PBKDF2-SHA256 hash."""
    if not stored_hash or "$" not in stored_hash:
        return False
    salt, h_hex = stored_hash.split("$", 1)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return secrets.compare_digest(h.hex(), h_hex)


def signup_lab(email: str, hostname: str, ip_address: str = None, password: str = None) -> tuple[str, str]:
    """Self-service signup. Creates a lab + signup record atomically. Returns (lab_id, token)."""
    lab_id = str(uuid4())
    token = secrets.token_hex(32)
    pw_hash = _hash_password(password) if password else None
    now = datetime.now(timezone.utc).isoformat()

    # Inherit plan from existing account (so Pro users don't get downgraded on new nodes)
    existing_plan = get_plan_for_email(email)

    conn = _connect()
    try:
        conn.execute(
            """INSERT INTO labs (id, hostname, os, arch, agent_version, token, registered_at, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (lab_id, hostname, "linux", "amd64", "pending-install", token, now, now),
        )
        conn.execute(
            "INSERT INTO signups (email, password_hash, lab_id, plan, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (email, pw_hash, lab_id, existing_plan, ip_address, now),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return lab_id, token


_DUMMY_HASH = _hash_password("dummy-timing-normalization")

def verify_login(email: str, password: str) -> bool:
    """Verify email + password login. Returns True if credentials match."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT password_hash FROM signups WHERE email = ? ORDER BY created_at DESC LIMIT 1",
            (email,),
        ).fetchone()
        if not row or not row["password_hash"]:
            # Normalize timing to prevent email enumeration
            _verify_password(password, _DUMMY_HASH)
            return False
        return _verify_password(password, row["password_hash"])
    finally:
        conn.close()


def set_password_for_email(email: str, password: str) -> bool:
    """Set/update password for an existing account. Returns True if account existed."""
    pw_hash = _hash_password(password)
    conn = _connect()
    try:
        cursor = conn.execute(
            "UPDATE signups SET password_hash = ? WHERE email = ?",
            (pw_hash, email),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def email_has_password(email: str) -> bool:
    """Check if an email account has a password set."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT password_hash FROM signups WHERE email = ? ORDER BY created_at DESC LIMIT 1",
            (email,),
        ).fetchone()
        return bool(row and row["password_hash"])
    finally:
        conn.close()


def check_signup_rate(ip_address: str, max_per_hour: int = 5) -> bool:
    """Returns True if the IP is under the signup rate limit."""
    conn = _connect()
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        row = conn.execute(
            "SELECT COUNT(*) FROM signups WHERE ip_address = ? AND created_at > ?",
            (ip_address, cutoff),
        ).fetchone()
        return row[0] < max_per_hour
    finally:
        conn.close()


def count_labs_for_email(email: str) -> int:
    """Count how many labs an email has registered."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM signups WHERE email = ?",
            (email,),
        ).fetchone()
        return row[0]
    finally:
        conn.close()


def get_email_for_lab(lab_id: str) -> Optional[str]:
    """Get the email address associated with a lab (via signups table)."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT email FROM signups WHERE lab_id = ?", (lab_id,)
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def email_owns_lab(email: str, lab_id: str) -> bool:
    """Check if a lab belongs to the given email."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM signups WHERE email = ? AND lab_id = ?", (email, lab_id)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def delete_account(email: str) -> None:
    """Delete a user account and all associated data (GDPR right to erasure)."""
    conn = _connect()
    try:
        # Get all lab IDs for this email
        lab_ids = [r[0] for r in conn.execute(
            "SELECT lab_id FROM signups WHERE email = ?", (email,)
        ).fetchall()]
        # Delete metrics, alerts, digests for all labs
        for lid in lab_ids:
            conn.execute("DELETE FROM metrics WHERE lab_id = ?", (lid,))
            conn.execute("DELETE FROM alerts WHERE lab_id = ?", (lid,))
            conn.execute("DELETE FROM digests WHERE lab_id = ?", (lid,))
            conn.execute("DELETE FROM labs WHERE id = ?", (lid,))
        # Delete user preferences
        conn.execute("DELETE FROM user_preferences WHERE email = ?", (email,))
        # Delete user notification channels
        conn.execute("DELETE FROM notification_channels WHERE owner_email = ?", (email,))
        # Delete signup records
        conn.execute("DELETE FROM signups WHERE email = ?", (email,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_labs_for_email(email: str) -> list[dict[str, Any]]:
    """Get all labs associated with an email address."""
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT l.* FROM labs l
               JOIN signups s ON l.id = s.lab_id
               WHERE s.email = ?
               ORDER BY l.registered_at DESC""",
            (email,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_lab(lab_id: str) -> Optional[dict[str, Any]]:
    """Get lab by ID."""
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM labs WHERE id = ?", (lab_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_lab_by_token(token: str) -> Optional[dict[str, Any]]:
    """Get lab by its auth token."""
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM labs WHERE token = ?", (token,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_labs() -> list[dict[str, Any]]:
    """List all registered labs."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM labs ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def store_metrics(lab_id: str, metric_type: str, data: Any) -> None:
    """Store a metrics snapshot."""
    now = datetime.now(timezone.utc).isoformat()
    data_json = json.dumps(data) if not isinstance(data, str) else data

    conn = _connect()
    try:
        conn.execute(
            """INSERT INTO metrics (lab_id, timestamp, metric_type, data, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (lab_id, now, metric_type, data_json, now),
        )
        conn.commit()
    finally:
        conn.close()


def store_metrics_batch(lab_id: str, collectors: dict[str, Any]) -> list[str]:
    """Store multiple collector types in a single transaction. Returns stored types."""
    now = datetime.now(timezone.utc).isoformat()
    conn = _connect()
    try:
        stored = []
        for metric_type, data in collectors.items():
            data_json = json.dumps(data) if not isinstance(data, str) else data
            conn.execute(
                """INSERT INTO metrics (lab_id, timestamp, metric_type, data, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (lab_id, now, metric_type, data_json, now),
            )
            stored.append(metric_type)
        conn.execute("UPDATE labs SET last_seen = ? WHERE id = ?", (now, lab_id))
        conn.commit()
        return stored
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_latest_metrics(lab_id: str) -> dict[str, Any]:
    """Get the most recent metric of each type for a lab (single query)."""
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT m.* FROM metrics m
               INNER JOIN (
                   SELECT metric_type, MAX(timestamp) AS max_ts
                   FROM metrics WHERE lab_id = ?
                   GROUP BY metric_type
               ) latest ON m.lab_id = ? AND m.metric_type = latest.metric_type
                       AND m.timestamp = latest.max_ts""",
            (lab_id, lab_id),
        ).fetchall()

        result = {}
        for row in rows:
            entry = dict(row)
            entry["data"] = json.loads(entry["data"])
            result[entry["metric_type"]] = entry

        return result
    finally:
        conn.close()


def get_recent_system_samples(lab_id: str, count: int = 2) -> list[dict]:
    """Get the N most recent system metrics samples for rate calculations."""
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT data, timestamp FROM metrics
               WHERE lab_id = ? AND metric_type = 'system'
               ORDER BY timestamp DESC LIMIT ?""",
            (lab_id, count),
        ).fetchall()
        return [{"data": json.loads(r["data"]), "timestamp": r["timestamp"]} for r in rows]
    finally:
        conn.close()


def get_metrics_history(lab_id: str, hours: int = 24, limit: int = 5000) -> list[dict[str, Any]]:
    """Get metrics history for a lab within the given time window."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT * FROM metrics
               WHERE lab_id = ? AND timestamp > ?
               ORDER BY timestamp DESC LIMIT ?""",
            (lab_id, cutoff, limit),
        ).fetchall()

        result = []
        for r in rows:
            entry = dict(r)
            entry["data"] = json.loads(entry["data"])
            result.append(entry)
        return result
    finally:
        conn.close()


def update_last_seen(lab_id: str) -> None:
    """Touch the last_seen timestamp for a lab."""
    now = datetime.now(timezone.utc).isoformat()
    conn = _connect()
    try:
        conn.execute("UPDATE labs SET last_seen = ? WHERE id = ?", (now, lab_id))
        conn.commit()
    finally:
        conn.close()


def delete_lab(lab_id: str) -> bool:
    """Delete a lab and all its metrics/alerts. Returns True if lab existed."""
    conn = _connect()
    try:
        cursor = conn.execute("DELETE FROM labs WHERE id = ?", (lab_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def store_alert(
    lab_id: str,
    alert_type: str,
    severity: str,
    message: str,
    data: Any = None,
    cooldown_minutes: int = 15,
) -> tuple[int, bool]:
    """Store an alert with deduplication. Returns (alert_id, is_new).

    When an existing unresolved alert of the same type exists, updates it
    and returns (existing_id, False). Otherwise inserts and returns (new_id, True).

    To prevent notification spam from threshold oscillation, if an alert of the
    same type was resolved within ``cooldown_minutes``, the alert is inserted
    but ``is_new`` is returned as False (suppressing re-notification).
    """
    now = datetime.now(timezone.utc).isoformat()
    data_json = json.dumps(data or {})

    conn = _connect()
    try:
        # BEGIN IMMEDIATE to hold write lock across read+conditional-write (prevents TOCTOU race)
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            """SELECT id FROM alerts
               WHERE lab_id = ? AND alert_type = ? AND resolved_at IS NULL
               LIMIT 1""",
            (lab_id, alert_type),
        ).fetchone()
        if existing:
            # Update message but don't create duplicate
            conn.execute(
                "UPDATE alerts SET message = ?, data = ? WHERE id = ?",
                (message, data_json, existing["id"]),
            )
            conn.commit()
            return existing["id"], False

        # Check if same alert type was recently resolved (oscillation guard)
        cooldown_cutoff = (
            datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)
        ).isoformat()
        recently_resolved = conn.execute(
            """SELECT id FROM alerts
               WHERE lab_id = ? AND alert_type = ? AND resolved_at > ?
               LIMIT 1""",
            (lab_id, alert_type, cooldown_cutoff),
        ).fetchone()

        cursor = conn.execute(
            """INSERT INTO alerts (lab_id, alert_type, severity, message, data, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (lab_id, alert_type, severity, message, data_json, now),
        )
        conn.commit()
        # Suppress is_new if within cooldown — alert is stored but no notification fires
        return cursor.lastrowid, (recently_resolved is None)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def resolve_alerts(lab_id: str, alert_types: list[str]) -> int:
    """Resolve alerts of given types for a lab. Returns count resolved."""
    now = datetime.now(timezone.utc).isoformat()
    if not alert_types:
        return 0
    placeholders = ",".join("?" * len(alert_types))
    conn = _connect()
    try:
        cursor = conn.execute(
            f"""UPDATE alerts SET resolved_at = ?
                WHERE lab_id = ? AND alert_type IN ({placeholders})
                AND resolved_at IS NULL""",
            [now, lab_id] + alert_types,
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_active_alerts(lab_id: str) -> list[dict[str, Any]]:
    """Get unresolved alerts for a lab."""
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT * FROM alerts
               WHERE lab_id = ? AND resolved_at IS NULL
               ORDER BY created_at DESC""",
            (lab_id,),
        ).fetchall()

        result = []
        for r in rows:
            entry = dict(r)
            entry["data"] = json.loads(entry["data"])
            result.append(entry)
        return result
    finally:
        conn.close()


def get_alerts_in_range(
    lab_id: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Get alerts within a time range, optionally filtered by lab_id."""
    conn = _connect()
    try:
        conditions = []
        params: list[Any] = []

        if lab_id:
            conditions.append("lab_id = ?")
            params.append(lab_id)
        if start:
            conditions.append("created_at >= ?")
            params.append(start)
        if end:
            conditions.append("created_at <= ?")
            params.append(end)

        where = " AND ".join(conditions) if conditions else "1=1"
        rows = conn.execute(
            f"SELECT * FROM alerts WHERE {where} ORDER BY created_at DESC LIMIT 10000",
            params,
        ).fetchall()

        result = []
        for r in rows:
            entry = dict(r)
            entry["data"] = json.loads(entry["data"])
            result.append(entry)
        return result
    finally:
        conn.close()


def get_all_active_alerts() -> list[dict[str, Any]]:
    """Get all unresolved alerts across all labs."""
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT a.*, l.hostname FROM alerts a
               JOIN labs l ON a.lab_id = l.id
               WHERE a.resolved_at IS NULL
               ORDER BY a.created_at DESC"""
        ).fetchall()

        result = []
        for r in rows:
            entry = dict(r)
            entry["data"] = json.loads(entry["data"])
            result.append(entry)
        return result
    finally:
        conn.close()


def get_recent_alerts_feed(limit: int = 20) -> list[dict[str, Any]]:
    """Get recent alerts (both active and resolved) for the alert feed widget."""
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT a.*, l.hostname FROM alerts a
               JOIN labs l ON a.lab_id = l.id
               ORDER BY a.created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        result = []
        for r in rows:
            entry = dict(r)
            entry["data"] = json.loads(entry["data"])
            result.append(entry)
        return result
    finally:
        conn.close()


def get_uptime_segments(hours: int = 24) -> dict[str, list[dict]]:
    """Get uptime/downtime segments for each lab over the given time window.

    Returns {lab_id: [{start, end, status}]} where status is 'online', 'stale', or 'offline'.
    Uses metrics timestamps to determine when nodes were reporting.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    conn = _connect()
    try:
        # Get all labs
        labs = conn.execute("SELECT id, hostname, last_seen FROM labs").fetchall()
        result = {}
        for lab in labs:
            lab_id = lab["id"]
            # Get all metric timestamps in the window
            rows = conn.execute(
                """SELECT timestamp FROM metrics
                   WHERE lab_id = ? AND timestamp > ?
                   ORDER BY timestamp ASC""",
                (lab_id, cutoff),
            ).fetchall()
            timestamps = [r["timestamp"] for r in rows]
            segments = _build_uptime_segments(timestamps, hours)
            result[lab_id] = {
                "hostname": lab["hostname"],
                "segments": segments,
            }
        return result
    finally:
        conn.close()


def _build_uptime_segments(timestamps: list[str], window_hours: int) -> list[dict]:
    """Build uptime segments from a list of metric timestamps.

    A gap > 3 minutes between reports = offline segment.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    segments = []
    gap_threshold = timedelta(minutes=3)

    if not timestamps:
        # No data — entire window is offline
        return [{"start": window_start.isoformat(), "end": now.isoformat(), "status": "offline"}]

    # Start with gap from window start to first timestamp
    first_ts = datetime.fromisoformat(timestamps[0])
    if first_ts - window_start > gap_threshold:
        segments.append({"start": window_start.isoformat(), "end": timestamps[0], "status": "offline"})

    # Walk through timestamps, detecting gaps
    seg_start = timestamps[0]
    prev_ts = first_ts
    for ts_str in timestamps[1:]:
        ts = datetime.fromisoformat(ts_str)
        if ts - prev_ts > gap_threshold:
            # Close online segment, add offline gap
            segments.append({"start": seg_start, "end": prev_ts.isoformat(), "status": "online"})
            segments.append({"start": prev_ts.isoformat(), "end": ts_str, "status": "offline"})
            seg_start = ts_str
        prev_ts = ts

    # Close final online segment
    last_ts = datetime.fromisoformat(timestamps[-1])
    if now - last_ts > gap_threshold:
        segments.append({"start": seg_start, "end": timestamps[-1], "status": "online"})
        segments.append({"start": timestamps[-1], "end": now.isoformat(), "status": "offline"})
    else:
        segments.append({"start": seg_start, "end": now.isoformat(), "status": "online"})

    return segments


def get_metric_sparkline(lab_id: str, metric_path: str, hours: int = 1, points: int = 30) -> list[dict]:
    """Get sampled metric values for sparkline rendering.

    metric_path: 'cpu', 'memory', or 'disk' — extracts from system metrics.
    Returns [{timestamp, value}] sampled to ~points entries.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT timestamp, data FROM metrics
               WHERE lab_id = ? AND metric_type = 'system' AND timestamp > ?
               ORDER BY timestamp ASC""",
            (lab_id, cutoff),
        ).fetchall()

        values = []
        for r in rows:
            data = json.loads(r["data"])
            val = None
            if metric_path == "cpu":
                cpu = data.get("cpu", {})
                val = cpu.get("total_percent") if isinstance(cpu, dict) else None
            elif metric_path == "memory":
                mem = data.get("memory", {})
                val = mem.get("used_percent") if isinstance(mem, dict) else None
            elif metric_path == "disk":
                disks = data.get("disk", [])
                val = disks[0].get("used_percent") if isinstance(disks, list) and disks else None
            if val is not None:
                values.append({"timestamp": r["timestamp"], "value": round(val, 1)})

        # Downsample if too many points
        if len(values) > points:
            step = len(values) / points
            sampled = []
            for i in range(points):
                idx = int(i * step)
                sampled.append(values[idx])
            return sampled
        return values
    finally:
        conn.close()


def purge_old_metrics(hours: int = 24) -> int:
    """Remove metrics older than the given hours. Returns count deleted."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    conn = _connect()
    try:
        cursor = conn.execute(
            "DELETE FROM metrics WHERE created_at < ?", (cutoff,)
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_plan_for_email(email: str, default: str = "free") -> str:
    """Look up the most recent plan string for a signup email."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT plan FROM signups WHERE email = ? ORDER BY created_at DESC LIMIT 1",
            (email,),
        ).fetchone()
        return row[0] if row and row[0] else default
    finally:
        conn.close()


def set_plan_for_email(email: str, plan: str) -> int:
    """Set the plan for every signup row belonging to this email.
    Returns the number of rows updated. Caller is responsible for validating
    the plan string against TIER_LIMITS.
    """
    conn = _connect()
    try:
        cursor = conn.execute(
            "UPDATE signups SET plan = ? WHERE email = ?",
            (plan, email),
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def is_stripe_event_processed(event_id: str) -> bool:
    """Check if a Stripe event has already been processed (idempotency)."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM stripe_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def claim_stripe_event(event_id: str) -> bool:
    """Atomically claim a Stripe event for processing.

    Returns True if this call won the claim (proceed with processing),
    False if the event was already processed (skip).
    """
    now = datetime.now(timezone.utc).isoformat()
    conn = _connect()
    try:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO stripe_events (event_id, processed_at) VALUES (?, ?)",
            (event_id, now),
        )
        conn.commit()
        return cursor.rowcount == 1
    finally:
        conn.close()


def mark_stripe_event_processed(event_id: str) -> None:
    """Record a Stripe event as processed (legacy — prefer claim_stripe_event)."""
    now = datetime.now(timezone.utc).isoformat()
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO stripe_events (event_id, processed_at) VALUES (?, ?)",
            (event_id, now),
        )
        conn.commit()
    finally:
        conn.close()


def purge_metrics_per_tier(tier_limits: dict, default_plan: str = "free") -> int:
    """Purge metrics per-lab using each lab owner's tier retention window.
    Labs with no associated signup (legacy/demo rows) fall back to the
    default plan's retention. Returns total rows deleted.
    """
    now = datetime.now(timezone.utc)
    default_hours = (
        tier_limits.get(default_plan, {}).get("retention_hours")
        or 24 * 30
    )

    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT l.id AS lab_id, s.plan AS plan "
            "FROM labs l LEFT JOIN signups s ON s.lab_id = l.id"
        ).fetchall()

        total = 0
        for row in rows:
            plan = row["plan"] or default_plan
            limits = tier_limits.get(plan) or tier_limits.get(default_plan) or {}
            hours = limits.get("retention_hours") or default_hours
            cutoff = (now - timedelta(hours=hours)).isoformat()
            cursor = conn.execute(
                "DELETE FROM metrics WHERE lab_id = ? AND created_at < ?",
                (row["lab_id"], cutoff),
            )
            total += cursor.rowcount

        # Orphan metrics (lab_id not in labs) — purge using default plan window.
        orphan_cutoff = (now - timedelta(hours=default_hours)).isoformat()
        cursor = conn.execute(
            "DELETE FROM metrics WHERE created_at < ? "
            "AND lab_id NOT IN (SELECT id FROM labs)",
            (orphan_cutoff,),
        )
        total += cursor.rowcount

        conn.commit()
        return total
    finally:
        conn.close()


def purge_old_alerts(hours: int = 720) -> int:
    """Remove alerts older than the given hours. Returns count deleted."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    conn = _connect()
    try:
        cursor = conn.execute(
            "DELETE FROM alerts WHERE created_at < ?", (cutoff,)
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def log_nlq_query(
    question: str,
    query_type: str,
    matched: bool,
    confidence: float = 0.0,
    email: str | None = None,
) -> None:
    """Log an NLQ query for analytics (non-fatal if table doesn't exist)."""
    conn = _connect()
    try:
        conn.execute(
            """INSERT INTO nlq_log (question, query_type, matched, confidence, email, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (question, query_type, matched, confidence, email,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    except Exception:
        pass  # Table may not exist yet — non-critical
    finally:
        conn.close()


def list_active_maintenance(lab_ids: list[str]) -> dict[str, dict]:
    """Return {lab_id: maintenance_state} for labs currently in maintenance mode."""
    if not lab_ids:
        return {}
    conn = _connect()
    try:
        placeholders = ",".join("?" for _ in lab_ids)
        rows = conn.execute(
            f"""SELECT lab_id, reason, started_at, ends_at FROM maintenance
                WHERE lab_id IN ({placeholders})
                  AND enabled = 1
                  AND (ends_at IS NULL OR ends_at > ?)""",
            (*lab_ids, datetime.now(timezone.utc).isoformat()),
        ).fetchall()
        return {
            r["lab_id"]: {"reason": r["reason"], "started_at": r["started_at"], "ends_at": r["ends_at"]}
            for r in rows
        }
    except Exception:
        return {}  # Table may not exist yet — maintenance is a future feature
    finally:
        conn.close()


def get_lab_stats(lab_id: str) -> dict[str, Any]:
    """Get summary stats for a lab."""
    conn = _connect()
    try:
        metric_count = conn.execute(
            "SELECT COUNT(*) as c FROM metrics WHERE lab_id = ?", (lab_id,)
        ).fetchone()["c"]

        alert_count = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE lab_id = ? AND resolved_at IS NULL",
            (lab_id,),
        ).fetchone()["c"]

        return {
            "metric_count": metric_count,
            "active_alerts": alert_count,
        }
    finally:
        conn.close()


def store_digest(lab_id: str, period_start: str, period_end: str, summary: str, data: Any = None) -> int:
    """Store a digest."""
    now = datetime.now(timezone.utc).isoformat()
    data_json = json.dumps(data or {})
    conn = _connect()
    try:
        cursor = conn.execute(
            """INSERT INTO digests (lab_id, period_start, period_end, summary, data, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (lab_id, period_start, period_end, summary, data_json, now),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_latest_digest(lab_id: str) -> Optional[dict[str, Any]]:
    """Get the most recent digest for a lab."""
    conn = _connect()
    try:
        row = conn.execute(
            """SELECT * FROM digests WHERE lab_id = ? ORDER BY created_at DESC LIMIT 1""",
            (lab_id,),
        ).fetchone()
        if row:
            entry = dict(row)
            entry["data"] = json.loads(entry["data"])
            return entry
        return None
    finally:
        conn.close()


def get_metrics_summary(lab_id: str, hours: int = 168) -> dict[str, Any]:
    """Get aggregated metrics stats for digest generation."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT * FROM metrics
               WHERE lab_id = ? AND metric_type = 'system' AND timestamp > ?
               ORDER BY timestamp ASC""",
            (lab_id, cutoff),
        ).fetchall()

        if not rows:
            return {"sample_count": 0}

        cpu_vals = []
        mem_vals = []
        disk_vals = []
        load_vals = []

        for r in rows:
            data = json.loads(r["data"])
            cpu = data.get("cpu", {})
            mem = data.get("memory", {})
            disks = data.get("disk", [])
            load_avg = data.get("load_average", {})

            if isinstance(cpu, dict) and cpu.get("total_percent") is not None:
                cpu_vals.append(cpu["total_percent"])
            if isinstance(mem, dict) and mem.get("used_percent") is not None:
                mem_vals.append(mem["used_percent"])
            if isinstance(disks, list) and disks:
                dp = disks[0].get("used_percent")
                if dp is not None:
                    disk_vals.append(dp)
            if isinstance(load_avg, dict):
                l1 = load_avg.get("load1")
                if l1 is not None:
                    load_vals.append(l1)
            elif isinstance(load_avg, (list, tuple)) and load_avg:
                load_vals.append(load_avg[0])

        def stats(vals):
            if not vals:
                return {"min": 0, "max": 0, "avg": 0, "current": 0}
            return {
                "min": round(min(vals), 2),
                "max": round(max(vals), 2),
                "avg": round(sum(vals) / len(vals), 2),
                "current": round(vals[-1], 2),
            }

        # Count alerts in period
        alert_count = conn.execute(
            """SELECT COUNT(*) as c FROM alerts
               WHERE lab_id = ? AND created_at > ?""",
            (lab_id, cutoff),
        ).fetchone()["c"]

        resolved_count = conn.execute(
            """SELECT COUNT(*) as c FROM alerts
               WHERE lab_id = ? AND created_at > ? AND resolved_at IS NOT NULL""",
            (lab_id, cutoff),
        ).fetchone()["c"]

        return {
            "sample_count": len(rows),
            "hours": hours,
            "cpu": stats(cpu_vals),
            "memory": stats(mem_vals),
            "disk": stats(disk_vals),
            "load": stats(load_vals),
            "alerts_total": alert_count,
            "alerts_resolved": resolved_count,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Notification Channels
# ---------------------------------------------------------------------------

def add_notification_channel(
    name: str,
    channel_type: str,
    config: Any = None,
    min_severity: str = "warning",
) -> int:
    """Create a notification channel. Returns channel id."""
    now = datetime.now(timezone.utc).isoformat()
    config_json = json.dumps(config or {})

    conn = _connect()
    try:
        cursor = conn.execute(
            """INSERT INTO notification_channels (name, channel_type, config, enabled, min_severity, created_at)
               VALUES (?, ?, ?, 1, ?, ?)""",
            (name, channel_type, config_json, min_severity, now),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def list_notification_channels() -> list[dict[str, Any]]:
    """Return global (admin) notification channels (owner_email IS NULL)."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM notification_channels WHERE owner_email IS NULL ORDER BY created_at DESC"
        ).fetchall()
        result = []
        for r in rows:
            entry = dict(r)
            try:
                entry["config"] = json.loads(entry["config"])
            except (json.JSONDecodeError, TypeError):
                entry["config"] = {}
            entry["enabled"] = bool(entry["enabled"])
            result.append(entry)
        return result
    finally:
        conn.close()


def list_user_notification_channels(email: str) -> list[dict[str, Any]]:
    """Return notification channels owned by a specific user."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM notification_channels WHERE owner_email = ? ORDER BY created_at DESC",
            (email,),
        ).fetchall()
        result = []
        for r in rows:
            entry = dict(r)
            try:
                entry["config"] = json.loads(entry["config"])
            except (json.JSONDecodeError, TypeError):
                entry["config"] = {}
            entry["enabled"] = bool(entry["enabled"])
            result.append(entry)
        return result
    finally:
        conn.close()


def add_user_notification_channel(
    email: str, name: str, channel_type: str, config: dict, min_severity: str = "warning",
) -> int:
    """Create a notification channel owned by a user. Returns the new channel id."""
    conn = _connect()
    try:
        cursor = conn.execute(
            """INSERT INTO notification_channels (name, channel_type, config, min_severity, owner_email, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, channel_type, json.dumps(config), min_severity, email,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def delete_user_notification_channel(email: str, channel_id: int) -> bool:
    """Delete a user-owned notification channel. Returns True if deleted."""
    conn = _connect()
    try:
        cursor = conn.execute(
            "DELETE FROM notification_channels WHERE id = ? AND owner_email = ?",
            (channel_id, email),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def get_notification_channel(channel_id: int) -> Optional[dict[str, Any]]:
    """Return a single notification channel by id."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM notification_channels WHERE id = ?", (channel_id,)
        ).fetchone()
        if row:
            entry = dict(row)
            try:
                entry["config"] = json.loads(entry["config"])
            except (json.JSONDecodeError, TypeError):
                entry["config"] = {}
            entry["enabled"] = bool(entry["enabled"])
            return entry
        return None
    finally:
        conn.close()


def update_notification_channel(channel_id: int, **kwargs) -> bool:
    """Update fields on a notification channel. Returns True if channel existed."""
    allowed = {"name", "config", "enabled", "min_severity"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return False

    # Serialize config to JSON if present
    if "config" in updates and not isinstance(updates["config"], str):
        updates["config"] = json.dumps(updates["config"])
    # Ensure enabled is stored as int
    if "enabled" in updates:
        updates["enabled"] = 1 if updates["enabled"] else 0

    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [channel_id]

    conn = _connect()
    try:
        cursor = conn.execute(
            f"UPDATE notification_channels SET {set_clause} WHERE id = ?",
            values,
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def delete_notification_channel(channel_id: int) -> bool:
    """Delete a notification channel. Returns True if it existed."""
    conn = _connect()
    try:
        cursor = conn.execute(
            "DELETE FROM notification_channels WHERE id = ?", (channel_id,)
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def get_enabled_channels(min_severity: str = "warning") -> list[dict[str, Any]]:
    """Return enabled channels with severity at or below the given level.

    Severity ordering: info(0) < warning(1) < critical(2).
    A channel with min_severity='warning' will receive warning and critical alerts.
    """
    severity_order = {"info": 0, "warning": 1, "critical": 2}
    threshold = severity_order.get(min_severity, 1)

    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM notification_channels WHERE enabled = 1"
        ).fetchall()
        result = []
        for r in rows:
            entry = dict(r)
            try:
                entry["config"] = json.loads(entry["config"])
            except (json.JSONDecodeError, TypeError):
                entry["config"] = {}
            entry["enabled"] = bool(entry["enabled"])
            ch_severity = severity_order.get(entry["min_severity"], 1)
            if ch_severity <= threshold:
                result.append(entry)
        return result
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# User Preferences: pins, thresholds, notifications
# ---------------------------------------------------------------------------

def _set_pref(email: str, pref_type: str, lab_id: Optional[str], data: dict) -> None:
    """Upsert a user preference."""
    now = datetime.now(timezone.utc).isoformat()
    conn = _connect()
    try:
        conn.execute("""
            INSERT INTO user_preferences (email, pref_type, lab_id, data, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(email, pref_type, COALESCE(lab_id, ''))
            DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
        """, (email, pref_type, lab_id, json.dumps(data), now))
        conn.commit()
    finally:
        conn.close()


def _get_pref(email: str, pref_type: str, lab_id: Optional[str] = None) -> Optional[dict]:
    """Get a single user preference."""
    conn = _connect()
    try:
        if lab_id is None:
            row = conn.execute(
                "SELECT data FROM user_preferences WHERE email = ? AND pref_type = ? AND lab_id IS NULL",
                (email, pref_type),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT data FROM user_preferences WHERE email = ? AND pref_type = ? AND lab_id = ?",
                (email, pref_type, lab_id),
            ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["data"])
        except (json.JSONDecodeError, TypeError):
            return None
    finally:
        conn.close()


def _delete_pref(email: str, pref_type: str, lab_id: Optional[str] = None) -> bool:
    """Delete a user preference. Returns True if a row was deleted."""
    conn = _connect()
    try:
        if lab_id is None:
            cur = conn.execute(
                "DELETE FROM user_preferences WHERE email = ? AND pref_type = ? AND lab_id IS NULL",
                (email, pref_type),
            )
        else:
            cur = conn.execute(
                "DELETE FROM user_preferences WHERE email = ? AND pref_type = ? AND lab_id = ?",
                (email, pref_type, lab_id),
            )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# --- Pin/favorite nodes ---

def pin_node(email: str, lab_id: str) -> None:
    _set_pref(email, "pinned_node", lab_id, {})


def unpin_node(email: str, lab_id: str) -> None:
    _delete_pref(email, "pinned_node", lab_id)


def get_pinned_nodes(email: str) -> list[str]:
    """Return list of pinned lab IDs for a user."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT lab_id FROM user_preferences WHERE email = ? AND pref_type = 'pinned_node'",
            (email,),
        ).fetchall()
        return [r["lab_id"] for r in rows]
    finally:
        conn.close()


# --- Custom alert thresholds ---

DEFAULT_THRESHOLDS = {
    "cpu_warning": 90,
    "memory_warning": 85,
    "memory_critical": 95,
    "disk_warning": 80,
    "disk_critical": 90,
    "gpu_util_warning": 90,
    "gpu_mem_warning": 90,
    "gpu_temp_warning": 85,
    "gpu_temp_critical": 95,
}


def set_alert_thresholds(email: str, lab_id: Optional[str], thresholds: dict) -> None:
    _set_pref(email, "alert_threshold", lab_id, thresholds)


def get_alert_thresholds(email: str, lab_id: Optional[str] = None) -> dict:
    """Get merged thresholds: defaults < global user prefs < per-node overrides."""
    result = dict(DEFAULT_THRESHOLDS)
    global_prefs = _get_pref(email, "alert_threshold", None)
    if global_prefs:
        result.update(global_prefs)
    if lab_id:
        node_prefs = _get_pref(email, "alert_threshold", lab_id)
        if node_prefs:
            result.update(node_prefs)
    return result


def delete_alert_thresholds(email: str, lab_id: str) -> bool:
    return _delete_pref(email, "alert_threshold", lab_id)


# --- Notification preferences ---

DEFAULT_NOTIFICATION_PREFS = {
    "cpu_high": True,
    "memory_high": True,
    "memory_critical": True,
    "disk_high": True,
    "disk_critical": True,
    "gpu_high": True,
    "gpu_temp_high": True,
    "container_restarts": True,
    "service_down": True,
}


def set_notification_prefs(email: str, prefs: dict) -> None:
    _set_pref(email, "notification_pref", None, prefs)


def get_notification_prefs(email: str) -> dict:
    """Get notification preferences, falling back to defaults."""
    result = dict(DEFAULT_NOTIFICATION_PREFS)
    user_prefs = _get_pref(email, "notification_pref", None)
    if user_prefs:
        result.update(user_prefs)
    return result


def vacuum() -> None:
    """Reclaim disk space after large deletes. Run after purge cycles."""
    conn = _connect()
    try:
        conn.execute('VACUUM')
    finally:
        conn.close()
