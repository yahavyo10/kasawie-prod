"""
Turns a raw window of logs (in whatever shape Elastic/Kibana exported it in)
into normalized LogEntry objects, then into per-device statistics.

This is the "narrow the haystack" step: instead of handing an LLM 5,000 raw
log lines, we compute cheap statistical signals per device first, and only
hand the LLM a short ranked shortlist with representative evidence.

Field aliases below cover every schema variant seen so far in real testing:
flat device_ip/device_name, ECS-style host.ip/host.name, and observer.ip/
observer.hostname (the Cisco-metrics-style schema). If a new export uses a
different nesting, add the dotted path here -- nothing else needs to change.
"""
import statistics
from typing import List, Dict, Any
from collections import defaultdict

from models import LogEntry, DeviceStats

TIMESTAMP_KEYS = ["@timestamp", "timestamp", "time", "date", "ts"]
IP_KEYS = [
    "device_ip", "ip", "source_ip", "src_ip", "host_ip",
    "device.ip", "host.ip", "observer.ip", "agent.ip", "clientip",
]
NAME_KEYS = [
    "device_name", "hostname", "host.name", "observer.hostname",
    "device", "agent.name", "host",
]
MESSAGE_KEYS = ["message", "msg", "log", "text", "event.original", "full_message"]
SEVERITY_KEYS = ["severity", "level", "log_level", "log.level", "syslog.severity"]

ERROR_SEVERITIES = {"error", "err", "critical", "crit", "emergency", "alert", "fatal", "warning", "warn"}


def _dig(d: Dict[str, Any], dotted_key: str):
    """Support both flat keys and dotted paths like 'host.ip' for nested dicts."""
    if dotted_key in d:
        return d[dotted_key]
    parts = dotted_key.split(".")
    cur = d
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def _first_present(d: Dict[str, Any], keys: List[str]):
    """Returns the first scalar (non-dict, non-list) value found across the
    candidate keys. Skipping non-scalars matters: e.g. a schema might have both
    top-level 'host' (a whole nested object) and 'host.name' (the string we
    actually want) -- without this guard, checking 'host' first would wrongly
    grab the entire object instead of the name."""
    for k in keys:
        v = _dig(d, k)
        if v is not None and v != "" and not isinstance(v, (dict, list)):
            return v
    return None


def normalize_logs(raw_logs: List[Dict[str, Any]]) -> List[LogEntry]:
    """Accepts a list of loosely-structured log dicts and returns LogEntry objects.
    Falls back gracefully when fields are missing rather than raising."""
    entries: List[LogEntry] = []
    for raw in raw_logs:
        if not isinstance(raw, dict):
            continue
        ip = _first_present(raw, IP_KEYS)
        name = _first_present(raw, NAME_KEYS)
        msg = _first_present(raw, MESSAGE_KEYS)
        ts = _first_present(raw, TIMESTAMP_KEYS)
        sev = _first_present(raw, SEVERITY_KEYS)

        entries.append(
            LogEntry(
                timestamp=str(ts) if ts is not None else None,
                device_ip=str(ip) if ip is not None else None,
                device_name=str(name) if name is not None else None,
                message=str(msg) if msg is not None else "",
                severity=str(sev).lower() if sev is not None else None,
                raw=raw,
            )
        )
    return entries


def _entity_key(entry: LogEntry) -> str:
    """The device identity we group by. Prefer IP; fall back to name; fall back to 'unknown'."""
    return entry.device_ip or entry.device_name or "unknown"


def compute_device_stats(entries: List[LogEntry]) -> List[DeviceStats]:
    """Group normalized logs by device and compute a composite anomaly score per device.

    Score components (all cheap, explainable, no black box):
      - concentration: this device's share of ALL error/warn logs in the window
        (a device that accounts for a disproportionate share of the window's
        errors is the strongest signal something is wrong specifically with it)
      - error_rate: fraction of this device's own logs that are error/warn severity
      - volume_z: how unusual this device's log volume is vs the average device
    """
    by_device: Dict[str, List[LogEntry]] = defaultdict(list)
    for e in entries:
        by_device[_entity_key(e)].append(e)

    total_error_logs = sum(
        1 for e in entries if (e.severity or "") in ERROR_SEVERITIES
    ) or 1  # avoid div by zero

    counts = [len(v) for v in by_device.values()]
    mean_count = statistics.mean(counts) if counts else 0
    stdev_count = statistics.pstdev(counts) if len(counts) > 1 else 1.0
    stdev_count = stdev_count or 1.0

    stats: List[DeviceStats] = []
    for device_key, logs in by_device.items():
        error_logs = [l for l in logs if (l.severity or "") in ERROR_SEVERITIES]
        error_rate = len(error_logs) / len(logs) if logs else 0.0
        concentration = len(error_logs) / total_error_logs
        volume_z = (len(logs) - mean_count) / stdev_count

        score = (concentration * 5.0) + (error_rate * 3.0) + (min(abs(volume_z), 4.0) * 0.5)

        device_ip = next((l.device_ip for l in logs if l.device_ip), device_key)
        device_name = next((l.device_name for l in logs if l.device_name), None)

        sample_pool = error_logs if error_logs else logs
        sample_messages = [l.message for l in sample_pool[:5] if l.message]

        stats.append(
            DeviceStats(
                device_ip=device_ip,
                device_name=device_name,
                log_count=len(logs),
                error_count=len(error_logs),
                error_rate=round(error_rate, 3),
                distinct_messages=len(set(l.message for l in logs)),
                anomaly_score=round(score, 3),
                sample_messages=sample_messages,
            )
        )

    stats.sort(key=lambda s: s.anomaly_score, reverse=True)
    return stats


def shortlist(stats: List[DeviceStats], top_n: int = 5) -> List[DeviceStats]:
    return stats[:top_n]
