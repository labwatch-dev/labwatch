"""Intelligence digest generator for labwatch."""

from datetime import datetime, timedelta, timezone
from typing import Any

from database import get_metrics_summary, store_digest, list_labs


def _build_narrative(hostname: str, data: dict, period_days: float) -> str:
    """Build a plain-English narrative about a node's health."""
    cpu_avg = data.get("cpu", {}).get("avg", 0)
    mem_avg = data.get("memory", {}).get("avg", 0)
    disk_cur = data.get("disk", {}).get("current", 0)
    load_avg = data.get("load", {}).get("avg", 0)
    alerts_total = data.get("alerts_total", 0)
    alerts_active = alerts_total - data.get("alerts_resolved", 0)
    samples = data.get("sample_count", 0)

    period = f"last {period_days:.0f} days" if period_days >= 1 else f"last {period_days * 24:.0f} hours"

    # Determine overall character
    if cpu_avg < 5 and mem_avg < 40 and load_avg < 5 and alerts_active == 0:
        opener = f"{hostname} had a quiet {period}. Running well below capacity with minimal activity."
    elif load_avg > 20 and cpu_avg < 20:
        opener = f"{hostname} is under heavy I/O pressure — high load average ({load_avg:.1f}) despite low CPU ({cpu_avg:.1f}%). This typically indicates disk or network bottlenecks."
    elif cpu_avg > 70:
        opener = f"{hostname} has been working hard. Sustained high CPU utilization ({cpu_avg:.1f}%) suggests a compute-heavy workload."
    elif alerts_active > 2:
        opener = f"{hostname} needs attention. Multiple unresolved alerts indicate ongoing issues."
    elif disk_cur > 80:
        opener = f"{hostname} is running tight on storage ({disk_cur:.1f}% used). Otherwise operating normally."
    else:
        opener = f"{hostname} has been running steadily over the {period}. No major issues detected."

    # Add color
    details = []
    if cpu_avg < 5:
        details.append(f"CPU usage averaged just {cpu_avg}% — this machine has significant headroom for additional workloads")
    elif cpu_avg > 50:
        details.append(f"CPU averaged {cpu_avg}%, suggesting a sustained workload that deserves monitoring")

    if mem_avg < 30:
        details.append(f"memory is comfortable at {mem_avg}%")
    elif mem_avg > 80:
        details.append(f"memory pressure is notable at {mem_avg}% — consider whether this node needs more RAM")

    if load_avg > 20:
        details.append(f"load average of {load_avg} is well above what the CPU count would suggest — likely I/O bound or thrashing")

    if alerts_active == 0 and alerts_total > 0:
        details.append(f"all {alerts_total} alerts that fired were resolved automatically")
    elif alerts_active > 0:
        details.append(f"{alerts_active} alert{'s' if alerts_active > 1 else ''} still unresolved")

    narrative = opener
    if details:
        narrative += " " + ". ".join(d.capitalize() if i == 0 and not d[0].isupper() else d for i, d in enumerate(details)) + "."

    return narrative


def generate_digest(lab_id: str, hostname: str, hours: int = 168) -> dict[str, Any]:
    """Generate a plain-English intelligence digest for a lab."""
    summary_data = get_metrics_summary(lab_id, hours=hours)

    if summary_data["sample_count"] == 0:
        text = f"No metrics data available for {hostname} in the last {hours} hours."
        return {"summary": text, "hostname": hostname, "grade": "?", "concerns": [], "highlights": [], "data": summary_data}

    period_days = hours / 24
    sections = []
    concerns = []
    highlights = []

    cpu = summary_data.get("cpu", {})
    mem = summary_data.get("memory", {})
    disk = summary_data.get("disk", {})
    load = summary_data.get("load", {})
    alerts_total = summary_data.get("alerts_total", 0)
    alerts_resolved = summary_data.get("alerts_resolved", 0)
    alerts_active = alerts_total - alerts_resolved

    # Build narrative summary
    narrative = _build_narrative(hostname, summary_data, period_days)
    sections.append(narrative)

    # CPU analysis
    if cpu.get("avg", 0) > 0:
        cpu_status = "idle" if cpu["avg"] < 10 else "moderate" if cpu["avg"] < 50 else "heavy" if cpu["avg"] < 80 else "critical"
        sections.append(f"**CPU**: {cpu['avg']}% avg ({cpu_status}), peaked at {cpu['max']}%, currently {cpu['current']}%")
        if cpu["max"] > 90:
            concerns.append(f"CPU peaked at {cpu['max']}% — investigate what process caused the spike")
        if cpu["avg"] < 5:
            highlights.append("CPU barely touched — significant spare capacity")

    # Memory analysis
    if mem.get("avg", 0) > 0:
        mem_range = abs(mem["max"] - mem["min"])
        mem_trend = "stable" if mem_range < 5 else "fluctuating" if mem_range < 20 else "volatile"
        sections.append(f"**Memory**: {mem['avg']}% avg ({mem_trend}), range {mem['min']}%-{mem['max']}%, currently {mem['current']}%")
        if mem["avg"] > 85:
            concerns.append(f"Memory consistently above 85% (avg {mem['avg']}%) — consider adding RAM or reducing workload")
        elif mem["avg"] > 70:
            concerns.append(f"Memory running warm at {mem['avg']}% average — monitor for growth")

    # Disk analysis
    if disk.get("avg", 0) > 0:
        sections.append(f"**Disk**: {disk['avg']}% avg, currently {disk['current']}%")
        disk_growth = disk["max"] - disk["min"]
        if disk_growth > 5:
            days_to_full = (100 - disk["current"]) / (disk_growth / period_days) if disk_growth > 0 else 999
            concerns.append(f"Disk grew by {disk_growth:.1f}% — at this rate, full in ~{days_to_full:.0f} days")
        if disk["current"] > 90:
            concerns.append(f"Disk at {disk['current']}% — CRITICAL. Clean up or expand storage immediately")
        elif disk["current"] > 80:
            concerns.append(f"Disk at {disk['current']}% — approaching warning threshold")

    # Load analysis
    if load.get("avg", 0) > 0:
        sections.append(f"**Load**: {load['avg']} avg (1m), peaked at {load['max']}, currently {load['current']}")
        if load["avg"] > 10:
            concerns.append(f"Sustained high load average ({load['avg']}) — system under consistent pressure")

    # Alerts
    if alerts_total > 0:
        sections.append(f"**Alerts**: {alerts_total} fired, {alerts_resolved} resolved, {alerts_active} active")
    else:
        sections.append("**Alerts**: Clean — zero alerts this period")
        highlights.append("Zero alerts — ran clean the entire period")

    # Concerns & Highlights
    if concerns:
        sections.append("### Concerns\n" + "\n".join(f"- {c}" for c in concerns))
    if highlights:
        sections.append("### Highlights\n" + "\n".join(f"- {h}" for h in highlights))

    # Grade
    grade = "A"
    if len(concerns) >= 3:
        grade = "C"
    elif len(concerns) >= 2:
        grade = "B-"
    elif len(concerns) >= 1:
        grade = "B+"

    sections.insert(1, f"**Health Grade: {grade}**")

    full_summary = "\n\n".join(sections)

    # Store it
    now = datetime.now(timezone.utc)
    period_start = (now - timedelta(hours=hours)).isoformat()
    period_end = now.isoformat()

    digest_id = store_digest(lab_id, period_start, period_end, full_summary, summary_data)

    return {
        "id": digest_id,
        "hostname": hostname,
        "grade": grade,
        "summary": full_summary,
        "concerns": concerns,
        "highlights": highlights,
        "data": summary_data,
    }


def generate_fleet_digest(hours: int = 168) -> dict[str, Any]:
    """Generate a digest for the entire fleet."""
    labs = list_labs()
    results = []
    fleet_concerns = []

    for lab in labs:
        result = generate_digest(lab["id"], lab["hostname"], hours=hours)
        results.append(result)
        for concern in result.get("concerns", []):
            fleet_concerns.append(f"**{lab['hostname']}**: {concern}")

    # Fleet overview
    grades = [r.get("grade", "?") for r in results]
    good = sum(1 for g in grades if g in ("A", "B+"))
    fair = sum(1 for g in grades if g in ("B-",))
    poor = sum(1 for g in grades if g in ("C", "D", "F"))

    fleet_summary = f"# Fleet Intelligence Digest\n\n"
    fleet_summary += f"**{len(labs)} nodes** monitored. {good} healthy, {fair} fair, {poor} need attention.\n\n"

    fleet_summary += "## Node Grades\n"
    for r in results:
        fleet_summary += f"- **{r['hostname']}**: {r.get('grade', '?')}\n"

    if fleet_concerns:
        fleet_summary += f"\n## Fleet Concerns ({len(fleet_concerns)})\n"
        for c in fleet_concerns:
            fleet_summary += f"- {c}\n"

    fleet_summary += f"\n---\n*Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*"

    return {
        "summary": fleet_summary,
        "nodes": results,
        "node_count": len(labs),
        "concerns_count": len(fleet_concerns),
    }
