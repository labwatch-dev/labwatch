"""Rule-based metrics analysis engine for labwatch."""

import logging
from typing import Any

import database as db
from database import store_alert, resolve_alerts
from notifications import send_alert_notification

logger = logging.getLogger("labwatch.analyzer")

# All possible alert types for auto-resolution
ALL_ALERT_TYPES = [
    "cpu_high", "memory_critical", "memory_high",
    "disk_critical", "disk_high", "load_high",
    "container_restarts", "service_failed",
    "gpu_high", "gpu_memory_high", "gpu_temp_high",
    "smart_unhealthy", "smart_temp_high", "smart_reallocated",
]


def _get_thresholds(lab_id: str) -> dict:
    """Get alert thresholds for a lab — custom if user has set them, else defaults."""
    email = db.get_email_for_lab(lab_id)
    if email:
        return db.get_alert_thresholds(email, lab_id)
    return dict(db.DEFAULT_THRESHOLDS)


def analyze_metrics(lab_id: str, metrics_data: dict[str, Any]) -> list[dict]:
    """
    Analyze ingested metrics and generate alerts based on threshold rules.
    Uses custom per-user/per-node thresholds if configured, otherwise defaults.

    metrics_data is the 'collectors' dict from the agent payload, keyed by
    collector type (system, docker, services).

    Returns a list of alert dicts that were created.
    """
    alerts: list[dict] = []
    thresholds = _get_thresholds(lab_id)

    system = metrics_data.get("system", {})
    docker = metrics_data.get("docker", {})
    services_data = metrics_data.get("services", {})

    cpu_warn = thresholds.get("cpu_warning", 90)
    mem_warn = thresholds.get("memory_warning", 85)
    mem_crit = thresholds.get("memory_critical", 95)
    disk_warn = thresholds.get("disk_warning", 80)
    disk_crit = thresholds.get("disk_critical", 90)

    # --- CPU (nested: system.cpu.total_percent) ---
    cpu = system.get("cpu", {})
    cpu_percent = cpu.get("total_percent") if isinstance(cpu, dict) else None
    if cpu_percent is not None and cpu_percent > cpu_warn:
        alert = _fire(
            lab_id,
            alert_type="cpu_high",
            severity="warning",
            message=f"CPU usage at {cpu_percent:.1f}% (threshold: {cpu_warn}%)",
            data={"cpu_percent": cpu_percent},
        )
        alerts.append(alert)

    # --- Memory (nested: system.memory.used_percent) ---
    mem = system.get("memory", {})
    mem_percent = mem.get("used_percent") if isinstance(mem, dict) else None
    if mem_percent is not None:
        if mem_percent > mem_crit:
            alert = _fire(
                lab_id,
                alert_type="memory_critical",
                severity="critical",
                message=f"Memory usage at {mem_percent:.1f}% (threshold: {mem_crit}%)",
                data={"memory_percent": mem_percent},
            )
            alerts.append(alert)
        elif mem_percent > mem_warn:
            alert = _fire(
                lab_id,
                alert_type="memory_high",
                severity="warning",
                message=f"Memory usage at {mem_percent:.1f}% (threshold: {mem_warn}%)",
                data={"memory_percent": mem_percent},
            )
            alerts.append(alert)

    # --- Disk (nested: system.disk[0].used_percent) ---
    disks = system.get("disk", [])
    disk_percent = disks[0].get("used_percent") if isinstance(disks, list) and disks else None
    if disk_percent is not None:
        if disk_percent > disk_crit:
            alert = _fire(
                lab_id,
                alert_type="disk_critical",
                severity="critical",
                message=f"Disk usage at {disk_percent:.1f}% (threshold: {disk_crit}%)",
                data={"disk_percent": disk_percent},
            )
            alerts.append(alert)
        elif disk_percent > disk_warn:
            alert = _fire(
                lab_id,
                alert_type="disk_high",
                severity="warning",
                message=f"Disk usage at {disk_percent:.1f}% (threshold: {disk_warn}%)",
                data={"disk_percent": disk_percent},
            )
            alerts.append(alert)

    # --- Load average vs CPU count ---
    load_avg = system.get("load_average", {})
    cpu_count = cpu.get("count") if isinstance(cpu, dict) else None
    if load_avg and cpu_count is not None:
        # Accept dict {load1, load5, load15}, list, or single float
        if isinstance(load_avg, dict):
            load_1m = load_avg.get("load1", 0)
        elif isinstance(load_avg, (list, tuple)) and len(load_avg) > 0:
            load_1m = load_avg[0]
        else:
            load_1m = load_avg

        threshold = cpu_count * 2
        if isinstance(load_1m, (int, float)) and load_1m > threshold:
            alert = _fire(
                lab_id,
                alert_type="load_high",
                severity="warning",
                message=f"Load average {load_1m:.2f} exceeds threshold ({threshold}) for {cpu_count} CPUs",
                data={"load_1m": load_1m, "cpu_count": cpu_count, "threshold": threshold},
            )
            alerts.append(alert)

    # --- Docker: container restart count ---
    containers = docker.get("containers", [])
    if isinstance(containers, list):
        for container in containers:
            restart_count = container.get("restart_count", 0)
            name = container.get("name", "unknown")
            if restart_count is not None and restart_count > 3:
                alert = _fire(
                    lab_id,
                    alert_type="container_restarts",
                    severity="warning",
                    message=f"Container '{name}' has restarted {restart_count} times",
                    data={"container": name, "restart_count": restart_count},
                )
                alerts.append(alert)

    # --- Services: check failures ---
    checks = services_data.get("services", []) if isinstance(services_data, dict) else (services_data if isinstance(services_data, list) else [])
    if isinstance(checks, list):
        for check in checks:
            healthy = check.get("healthy", True)
            name = check.get("name", "unknown")
            if not healthy:
                svc_status = check.get("status_code", "unhealthy")
                alert = _fire(
                    lab_id,
                    alert_type="service_failed",
                    severity="critical",
                    message=f"Service '{name}' health check failed",
                    data={"service": name, "status": svc_status},
                )
                alerts.append(alert)

    # --- GPU: utilization, memory, temperature ---
    gpu = metrics_data.get("gpu", {})
    gpu_devices = (gpu.get("devices") or []) if isinstance(gpu, dict) else []
    for device in gpu_devices:
        gpu_name = device.get("name", "GPU")
        gpu_idx = device.get("index", 0)

        gpu_util = device.get("utilization_percent")
        if gpu_util is not None and gpu_util > 90:
            alert = _fire(
                lab_id,
                alert_type="gpu_high",
                severity="warning",
                message=f"{gpu_name} (GPU {gpu_idx}) utilization at {gpu_util:.1f}% (threshold: 90%)",
                data={"gpu_index": gpu_idx, "gpu_name": gpu_name, "utilization_percent": gpu_util},
            )
            alerts.append(alert)

        gpu_mem = device.get("memory", {})
        gpu_mem_pct = gpu_mem.get("used_percent") if isinstance(gpu_mem, dict) else None
        if gpu_mem_pct is not None and gpu_mem_pct > 90:
            alert = _fire(
                lab_id,
                alert_type="gpu_memory_high",
                severity="warning",
                message=f"{gpu_name} (GPU {gpu_idx}) memory at {gpu_mem_pct:.1f}% (threshold: 90%)",
                data={"gpu_index": gpu_idx, "gpu_name": gpu_name, "memory_percent": gpu_mem_pct},
            )
            alerts.append(alert)

        gpu_temp = device.get("temperature_celsius")
        if gpu_temp is not None and gpu_temp > 85:
            alert = _fire(
                lab_id,
                alert_type="gpu_temp_high",
                severity="critical" if gpu_temp > 95 else "warning",
                message=f"{gpu_name} (GPU {gpu_idx}) temperature at {gpu_temp:.0f}°C (threshold: 85°C)",
                data={"gpu_index": gpu_idx, "gpu_name": gpu_name, "temperature": gpu_temp},
            )
            alerts.append(alert)

    # --- S.M.A.R.T. disk health (flat: smart.devices[]) ---
    smart = metrics_data.get("smart", {})
    smart_devices = smart.get("devices", []) if isinstance(smart, dict) else []
    if isinstance(smart_devices, list):
        for dev in smart_devices:
            if not isinstance(dev, dict):
                continue
            dev_name = dev.get("device", "unknown")
            model = dev.get("model") or dev.get("type") or ""
            label = f"{dev_name}" + (f" ({model})" if model else "")
            # Missing error field and healthy=False on reporting devices only
            if dev.get("error"):
                continue  # skip devices the agent couldn't query
            if dev.get("healthy") is False:
                alert = _fire(
                    lab_id,
                    alert_type="smart_unhealthy",
                    severity="critical",
                    message=f"Disk {label} SMART health: FAILED",
                    data={"device": dev_name, "model": model},
                )
                alerts.append(alert)
            temp = dev.get("temperature_c")
            if temp is not None and temp > 55:
                alert = _fire(
                    lab_id,
                    alert_type="smart_temp_high",
                    severity="critical" if temp > 65 else "warning",
                    message=f"Disk {label} temperature at {temp:.0f}°C (threshold: 55°C)",
                    data={"device": dev_name, "temperature_c": temp},
                )
                alerts.append(alert)
            reallocated = dev.get("reallocated_sector_ct", 0)
            if isinstance(reallocated, (int, float)) and reallocated > 0:
                alert = _fire(
                    lab_id,
                    alert_type="smart_reallocated",
                    severity="warning",
                    message=f"Disk {label} has {int(reallocated)} reallocated sector(s)",
                    data={"device": dev_name, "reallocated": int(reallocated)},
                )
                alerts.append(alert)

    # Auto-resolve alert types that didn't fire this cycle
    fired_types = {a["type"] for a in alerts}
    clear_types = [t for t in ALL_ALERT_TYPES if t not in fired_types]
    if clear_types:
        resolve_alerts(lab_id, clear_types)

    return alerts


def _fire(
    lab_id: str,
    alert_type: str,
    severity: str,
    message: str,
    data: dict,
) -> dict:
    """Store an alert, dispatch notifications for new alerts, and return summary dict."""
    alert_id, is_new = store_alert(lab_id, alert_type, severity, message, data)

    # Only send notifications for genuinely new alerts, not dedup updates
    if is_new:
        try:
            lab = db.get_lab(lab_id)
            if lab:
                send_alert_notification(
                    alert={"type": alert_type, "severity": severity, "message": message, "data": data},
                    lab=lab,
                )
        except Exception as e:
            logger.error(f"Failed to dispatch notifications for alert {alert_type} on lab {lab_id}: {e}")

    return {
        "id": alert_id,
        "lab_id": lab_id,
        "type": alert_type,
        "severity": severity,
        "message": message,
        "is_new": is_new,
    }
