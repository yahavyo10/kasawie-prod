"""
Phase 3: given a log file the user has already filtered down to one attacker
IP (e.g. an Elastic query scoped to source/client IP over up to a year), this
reconstructs: how long they've been present, which devices they touched, and
what level of access the evidence supports.

This intentionally reuses normalize_logs (aggregator.py), match_signatures
(signatures.py), and match_cve_database (cve_db.py) rather than duplicating
logic -- the "device" fields in each log entry here represent whatever the
attacker touched, not the attacker's own IP (the file is already scoped to
that), so the same field-alias parsing applies unchanged.
"""
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter, OrderedDict

from models import LogEntry


def compute_device_footprint(entries: List[LogEntry]) -> List[Dict[str, Any]]:
    """Per-device breakdown of everywhere this IP shows up: first/last seen,
    volume, and a severity breakdown, sorted by how much they touched each one."""
    by_device: Dict[str, List[LogEntry]] = defaultdict(list)
    for e in entries:
        key = e.device_ip or e.device_name or "unknown"
        by_device[key].append(e)

    footprint = []
    for key, logs in by_device.items():
        logs_sorted = sorted(logs, key=lambda l: l.timestamp or "")
        device_ip = next((l.device_ip for l in logs if l.device_ip), key)
        device_name = next((l.device_name for l in logs if l.device_name), None)
        severities = Counter(l.severity or "unknown" for l in logs)
        footprint.append({
            "device_ip": device_ip,
            "device_name": device_name,
            "log_count": len(logs),
            "first_seen": logs_sorted[0].timestamp if logs_sorted else None,
            "last_seen": logs_sorted[-1].timestamp if logs_sorted else None,
            "severity_breakdown": dict(severities),
        })

    footprint.sort(key=lambda f: f["log_count"], reverse=True)
    return footprint


def overall_span(entries: List[LogEntry]):
    """Earliest and latest timestamp across the entire filtered history --
    this is the raw material for "how long has this attacker been present"."""
    timestamps = sorted(e.timestamp for e in entries if e.timestamp)
    if not timestamps:
        return None, None
    return timestamps[0], timestamps[-1]


def condense_history(entries: List[LogEntry], max_groups_per_device: int = 6, max_total_groups: int = 60) -> List[Dict[str, Any]]:
    """Same idea as pipeline.condense_timeline, extended across a potentially
    year-long history: collapse repeated (device, message) pairs into one
    entry with a count and first/last timestamp, capped per device and
    overall, so token usage stays roughly constant regardless of how much
    history the user uploads."""
    by_device: Dict[str, "OrderedDict[str, Dict[str, Any]]"] = defaultdict(OrderedDict)
    for e in entries:
        device_key = e.device_ip or e.device_name or "unknown"
        msg_key = e.message
        groups = by_device[device_key]
        if msg_key not in groups:
            groups[msg_key] = {
                "device": device_key, "message": msg_key, "count": 0,
                "first_ts": e.timestamp, "last_ts": e.timestamp,
            }
        g = groups[msg_key]
        g["count"] += 1
        if e.timestamp and (g["last_ts"] is None or e.timestamp > g["last_ts"]):
            g["last_ts"] = e.timestamp
        if e.timestamp and (g["first_ts"] is None or e.timestamp < g["first_ts"]):
            g["first_ts"] = e.timestamp

    condensed: List[Dict[str, Any]] = []
    for device_key, groups in by_device.items():
        device_groups = list(groups.values())
        device_groups.sort(key=lambda g: g["count"], reverse=True)
        condensed.extend(device_groups[:max_groups_per_device])

    if len(condensed) > max_total_groups:
        condensed.sort(key=lambda g: g["count"], reverse=True)
        condensed = condensed[:max_total_groups]

    condensed.sort(key=lambda g: (g["device"], g["first_ts"] or ""))
    return condensed
