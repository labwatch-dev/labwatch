"""Basic tests for labwatch server — database and API endpoints.

Run with: python3 -m pytest test_labwatch.py -v
Requires: pip install pytest
"""

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

# Patch DATABASE_PATH before importing modules
_test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_test_db.close()

# Set env for config module
os.environ.setdefault("ADMIN_SECRET", "test-secret-for-tests")
os.environ.setdefault("SESSION_SECRET", "test-session-secret")

# Ensure server dir is on path
SERVER_DIR = Path(__file__).parent
sys.path.insert(0, str(SERVER_DIR))

import config
config.DATABASE_PATH = _test_db.name

import database as db


@pytest.fixture(scope="session", autouse=True)
def init_test_db():
    """Initialize test database once."""
    db.init_db()
    yield
    try:
        os.unlink(_test_db.name)
    except FileNotFoundError:
        pass
    for ext in ("-wal", "-shm"):
        try:
            os.unlink(_test_db.name + ext)
        except FileNotFoundError:
            pass


# ── Database Tests ──────────────────────────────────────────────


class TestSchemaVersion:
    def test_version_exists(self):
        version = db.get_schema_version()
        assert version >= 1

    def test_version_is_integer(self):
        version = db.get_schema_version()
        assert isinstance(version, int)


class TestLabRegistration:
    def test_register_lab(self):
        lab_id, token = db.register_lab("test-node", "linux", "amd64", "0.2.5")
        assert lab_id
        assert token
        assert len(token) == 64

    def test_get_lab(self):
        lab_id, token = db.register_lab("get-test", "linux", "arm64", "0.2.5")
        lab = db.get_lab(lab_id)
        assert lab is not None
        assert lab["hostname"] == "get-test"
        assert lab["os"] == "linux"
        assert lab["arch"] == "arm64"
        assert lab["agent_version"] == "0.2.5"

    def test_get_lab_by_token(self):
        lab_id, token = db.register_lab("token-test", "linux", "amd64", "0.2.5")
        lab = db.get_lab_by_token(token)
        assert lab is not None
        assert lab["id"] == lab_id

    def test_nonexistent_lab_returns_none(self):
        assert db.get_lab("nonexistent-id-12345") is None

    def test_list_labs(self):
        labs = db.list_labs()
        assert isinstance(labs, list)
        assert len(labs) >= 1

    def test_delete_lab(self):
        lab_id, _ = db.register_lab("delete-me", "linux", "amd64", "0.2.5")
        assert db.get_lab(lab_id) is not None
        db.delete_lab(lab_id)
        assert db.get_lab(lab_id) is None


class TestMetrics:
    def test_store_and_retrieve(self):
        lab_id, _ = db.register_lab("metrics-test", "linux", "amd64", "0.2.5")
        db.store_metrics(lab_id, "system", {
            "hostname": "metrics-test",
            "cpu": {"total_percent": 42.5},
            "memory": {"used_percent": 65.0, "used_bytes": 4_000_000_000},
            "disk": [{"mount": "/", "used_percent": 55.0}],
            "load_average": {"load1": 1.2, "load5": 0.9, "load15": 0.7},
            "uptime_seconds": 86400,
        })
        history = db.get_metrics_history(lab_id, hours=1)
        assert len(history) >= 1
        assert history[0]["metric_type"] == "system"

    def test_store_batch(self):
        lab_id, _ = db.register_lab("batch-test", "linux", "amd64", "0.2.5")
        types = db.store_metrics_batch(lab_id, {
            "system": {"hostname": "batch-test", "cpu": {"total_percent": 10}},
            "docker": {"containers": []},
        })
        assert "system" in types
        assert "docker" in types

    def test_latest_metrics(self):
        lab_id, _ = db.register_lab("latest-test", "linux", "amd64", "0.2.5")
        db.store_metrics(lab_id, "system", {"cpu": {"total_percent": 77}})
        latest = db.get_latest_metrics(lab_id)
        assert "system" in latest

    def test_purge_keeps_recent(self):
        lab_id, _ = db.register_lab("purge-test", "linux", "amd64", "0.2.5")
        db.store_metrics(lab_id, "system", {"cpu": {"total_percent": 10}})
        db.purge_old_metrics(hours=1)
        history = db.get_metrics_history(lab_id, hours=1)
        assert len(history) >= 1


class TestAlerts:
    def test_create_alert(self):
        lab_id, _ = db.register_lab("alert-test", "linux", "amd64", "0.2.5")
        db.store_alert(lab_id, "cpu_high", "warning", "CPU at 95%")
        alerts = db.get_active_alerts(lab_id)
        assert len(alerts) >= 1
        assert alerts[0]["alert_type"] == "cpu_high"

    def test_alert_deduplication(self):
        lab_id, _ = db.register_lab("dedup-test", "linux", "amd64", "0.2.5")
        db.store_alert(lab_id, "disk_high", "warning", "Disk at 85%")
        db.store_alert(lab_id, "disk_high", "warning", "Disk at 86%")
        alerts = db.get_active_alerts(lab_id)
        disk_alerts = [a for a in alerts if a["alert_type"] == "disk_high"]
        assert len(disk_alerts) == 1

    def test_resolve_alert(self):
        lab_id, _ = db.register_lab("resolve-test", "linux", "amd64", "0.2.5")
        db.store_alert(lab_id, "memory_high", "warning", "Memory at 90%")
        db.resolve_alerts(lab_id, ["memory_high"])
        alerts = db.get_active_alerts(lab_id)
        active_mem = [a for a in alerts if a["alert_type"] == "memory_high"]
        assert len(active_mem) == 0

    def test_all_active_alerts(self):
        alerts = db.get_all_active_alerts()
        assert isinstance(alerts, list)


class TestAccounts:
    def test_signup_and_login(self):
        lab_id, token = db.signup_lab("test@example.com", "signup-node", password="securepass123")
        assert lab_id
        assert token
        assert db.verify_login("test@example.com", "securepass123")
        assert not db.verify_login("test@example.com", "wrongpassword")

    def test_unknown_email_login_fails(self):
        assert not db.verify_login("nobody@example.com", "anypassword")

    def test_signup_rate_limit(self):
        assert db.check_signup_rate("10.0.0.1")

    def test_count_labs(self):
        db.signup_lab("counter@example.com", "node-1", password="pass1234")
        count = db.count_labs_for_email("counter@example.com")
        assert count >= 1


class TestNotifications:
    def test_add_channel(self):
        ch_id = db.add_notification_channel(
            name="test-ntfy",
            channel_type="ntfy",
            config={"server": "https://ntfy.sh", "topic": "test"},
            min_severity="warning",
        )
        assert ch_id

    def test_list_channels(self):
        channels = db.list_notification_channels()
        assert isinstance(channels, list)
        assert any(c["name"] == "test-ntfy" for c in channels)

    def test_delete_channel(self):
        ch_id = db.add_notification_channel(
            name="delete-me",
            channel_type="webhook",
            config={"url": "http://example.com"},
        )
        assert db.delete_notification_channel(ch_id)
        channels = db.list_notification_channels()
        assert not any(c["id"] == ch_id for c in channels)


class TestUserPreferences:
    def test_pin_unpin(self):
        lab_id, _ = db.register_lab("pin-test", "linux", "amd64", "0.2.5")
        db.pin_node("user@test.com", lab_id)
        pins = db.get_pinned_nodes("user@test.com")
        assert lab_id in pins

        db.unpin_node("user@test.com", lab_id)
        pins = db.get_pinned_nodes("user@test.com")
        assert lab_id not in pins

    def test_alert_thresholds(self):
        lab_id, _ = db.register_lab("threshold-test", "linux", "amd64", "0.2.5")
        thresholds = {"cpu_warning": 80, "disk_critical": 95}
        db.set_alert_thresholds("user@test.com", lab_id, thresholds)
        result = db.get_alert_thresholds("user@test.com", lab_id)
        assert result["cpu_warning"] == 80
        assert result["disk_critical"] == 95


class TestConfig:
    def test_tier_limits_defined(self):
        for plan in ("free", "pro", "business"):
            assert plan in config.TIER_LIMITS
            limits = config.TIER_LIMITS[plan]
            assert "retention_hours" in limits
            assert "node_cap" in limits

    def test_free_tier_limits(self):
        free = config.TIER_LIMITS["free"]
        assert free["node_cap"] == 3
        assert free["retention_hours"] == 30 * 24
