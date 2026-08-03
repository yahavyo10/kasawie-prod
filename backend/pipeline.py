"""
Orchestrates the two-phase investigation and yields a stream of step events.

Each yielded event is a plain dict:
    {"step": "<step_id>", "status": "start" | "done" | "error", "data": {...}}

main.py serializes these as Server-Sent Events so the frontend can render
the "thought process" live, step by step, instead of waiting for one big
final answer.
"""
from typing import List, Dict, Any, Optional, Generator
from collections import OrderedDict

from aggregator import normalize_logs, compute_device_stats, shortlist
from signatures import match_signatures
from cve_db import match_cve_database, CVEDefinition
from attacker_history import compute_device_footprint, overall_span, condense_history
from llm_client import call_llm_json, LLMError, FAST_MODEL
from models import LocalizationResult, TimelineEvent, NarrativeResult, AttackerHistoryResult


def _event(step: str, status: str, data: Any = None) -> Dict[str, Any]:
    return {"step": step, "status": status, "data": data}


def condense_timeline(timeline: List[TimelineEvent], max_groups: int = 30) -> List[Dict[str, Any]]:
    """Collapses repeated (window, message) pairs into one entry with a count and
    first/last timestamp. A brute-force burst of 200 near-identical "login failed"
    lines becomes ONE line in the prompt instead of 200 -- this is what keeps phase 2's
    token usage roughly constant no matter how large the input window is (critical once
    windows have thousands of logs -- otherwise this call blows past Groq's per-minute
    token limits). Full, uncollapsed events still go to the frontend timeline UI
    separately; this condensed version is only for what we send to the LLM."""
    groups: "OrderedDict[tuple, Dict[str, Any]]" = OrderedDict()
    for t in timeline:
        key = (t.window, t.message)
        if key not in groups:
            groups[key] = {"window": t.window, "message": t.message, "count": 0, "first_ts": t.timestamp, "last_ts": t.timestamp}
        g = groups[key]
        g["count"] += 1
        g["last_ts"] = t.timestamp  # timeline is chronological, so this stays the latest

    condensed = list(groups.values())
    if len(condensed) > max_groups:
        condensed.sort(key=lambda g: g["count"], reverse=True)
        condensed = condensed[:max_groups]
        condensed.sort(key=lambda g: (g["window"], g["first_ts"] or ""))
    return condensed


def run_phase1(window_t_raw: List[Dict[str, Any]]) -> Generator[Dict[str, Any], None, Optional[LocalizationResult]]:
    """Localize the root-cause device within the flagged anomaly window."""
    yield _event("ingest", "start", {"log_count": len(window_t_raw)})
    entries = normalize_logs(window_t_raw)
    yield _event("ingest", "done", {"parsed": len(entries)})

    yield _event("aggregate", "start", None)
    stats = compute_device_stats(entries)
    yield _event("aggregate", "done", {"devices": len(stats)})

    top = shortlist(stats, top_n=5)
    yield _event("shortlist", "done", {"candidates": [s.model_dump() for s in top]})

    if not top:
        yield _event("localize", "error", {"message": "No devices could be extracted from this window."})
        return None

    system_prompt = (
        "You are a network security analyst. You are given per-device statistics and "
        "representative log lines from a 5-minute window that an anomaly detector flagged "
        "as anomalous overall, WITHOUT saying which device caused it. Your job is to identify "
        "the single most likely responsible device using only the evidence given. "
        "Never invent an IP, message, or statistic that is not present in the input. "
        "Respond ONLY with a JSON object of this exact shape: "
        '{"device_ip": string, "device_name": string|null, "offending_message": string, '
        '"confidence": number between 0 and 1, "reasoning": [string, ...], "ruled_out": [string, ...]}. '
        "reasoning should be 3-5 short bullet-style strings explaining WHY this device was chosen, "
        "citing the actual numbers/messages you were given. ruled_out should briefly say why the "
        "next-most-suspicious 1-2 candidates were not chosen."
    )
    user_prompt = "Candidate devices, ranked by composite anomaly score (highest first):\n\n"
    for s in top:
        user_prompt += (
            f"- device_ip={s.device_ip} device_name={s.device_name} "
            f"log_count={s.log_count} error_count={s.error_count} error_rate={s.error_rate} "
            f"anomaly_score={s.anomaly_score}\n  sample_messages={s.sample_messages}\n"
        )

    yield _event("localize", "start", None)
    try:
        # Fast model here: this is a mostly-mechanical "pick from 5 ranked
        # candidates" call, optimized for low latency in the live demo.
        parsed = call_llm_json(system_prompt, user_prompt, model=FAST_MODEL)
        result = LocalizationResult(**parsed)
    except (LLMError, TypeError, ValueError) as e:
        yield _event("localize", "error", {"message": str(e)})
        return None

    yield _event("localize", "done", {"result": result.model_dump()})
    return result


def run_phase2(
    root_cause: LocalizationResult,
    window_t_raw: List[Dict[str, Any]],
    window_t1_raw: List[Dict[str, Any]],
    window_t2_raw: List[Dict[str, Any]],
    cve_defs: Optional[List[CVEDefinition]] = None,
) -> Generator[Dict[str, Any], None, Optional[NarrativeResult]]:
    """Build a grounded causal narrative from the 2 windows preceding the anomaly.
    cve_defs, if provided, is checked against the device's timeline via keyword
    indicators -- this can surface a known CVE even when the log text never
    literally writes out the CVE number (see cve_db.py)."""
    device_ip = root_cause.device_ip

    yield _event("timeline", "start", None)
    all_entries = []
    for window_name, raw in [("T-2", window_t2_raw), ("T-1", window_t1_raw), ("T", window_t_raw)]:
        entries = normalize_logs(raw)
        device_entries = [e for e in entries if e.device_ip == device_ip or e.device_name == device_ip]
        for e in device_entries:
            all_entries.append((window_name, e))

    timeline = [
        TimelineEvent(timestamp=e.timestamp, window=w, device_ip=device_ip, message=e.message)
        for w, e in all_entries
    ]
    yield _event("timeline", "done", {"events": [t.model_dump() for t in timeline], "count": len(timeline)})

    yield _event("signatures", "start", None)
    device_entries = [e for _, e in all_entries]
    matches = match_signatures(device_entries)
    db_matches = match_cve_database(device_entries, cve_defs or [])
    matches = matches + db_matches
    yield _event("signatures", "done", {
        "matches": [m.model_dump() for m in matches],
        "cve_database_checked": len(cve_defs or []),
        "cve_database_matched": len(db_matches),
    })

    system_prompt = (
        "You are a security incident analyst. You are given a chronological timeline of log "
        "lines for ONE device across the two windows before an anomaly plus the anomaly window "
        "itself, and a list of attack-pattern indicators that were matched by deterministic rules "
        "(not by you). Build a plausible causal narrative of what happened. "
        "CRITICAL RULE: only state a specific CVE identifier if it appears verbatim in the "
        "indicators' cve_ids field. If no CVE was matched, describe the pattern class instead "
        "(e.g. 'consistent with brute-force credential attack') and do not invent a CVE number. "
        "Timeline entries marked '(xN, first -> last)' represent N occurrences of a near-identical "
        "line collapsed into one entry -- treat the count and time span as real signal (a large N "
        "over a short span indicates a burst or automated attempt), not as missing detail. "
        "Do not assert that an action succeeded (e.g. a login succeeding) unless a line explicitly "
        "says so; if you infer it from later events, phrase it as an inference, not an observed fact. "
        "Double check which window (T-2, T-1, or T) an event actually belongs to before citing it. "
        "If the evidence is too thin for a confident attack narrative, say so plainly and suggest "
        "the most likely non-malicious explanation instead (misconfiguration, hardware fault, load spike). "
        'Respond ONLY with a JSON object of this exact shape: {"headline": string, "summary": string, '
        '"story_steps": [string, ...], "cited_cves": [string, ...], "confidence": number 0-1, "caveats": string}. '
        "story_steps should be 3-6 chronological steps of the narrative."
    )
    user_prompt = (
        f"Device under investigation: {device_ip} ({root_cause.device_name})\n"
        f"Root cause message that triggered the anomaly: {root_cause.offending_message}\n\n"
        f"Timeline (chronological, oldest first; repeated near-identical lines are "
        f"collapsed into one entry with a count and first/last timestamp):\n"
    )
    condensed = condense_timeline(timeline)
    for c in condensed:
        if c["count"] > 1:
            user_prompt += f"- [{c['window']}] {c['message']}  (x{c['count']}, {c['first_ts']} -> {c['last_ts']})\n"
        else:
            user_prompt += f"- [{c['window']}] {c['first_ts'] or 'unknown time'}: {c['message']}\n"

    user_prompt += "\nMatched attack-pattern indicators (ground truth, do not exceed these):\n"
    if matches:
        for m in matches:
            user_prompt += f"- {m.name}: {m.description} | cve_ids={m.cve_ids} | example_lines={m.matched_lines[:3]}\n"
    else:
        user_prompt += "- none matched\n"

    yield _event("narrate", "start", None)
    try:
        parsed = call_llm_json(system_prompt, user_prompt)
        result = NarrativeResult(**parsed)
    except (LLMError, TypeError, ValueError) as e:
        yield _event("narrate", "error", {"message": str(e)})
        return None

    yield _event("narrate", "done", {"result": result.model_dump()})
    return result


def run_phase3_attacker_history(
    raw_logs: List[Dict[str, Any]],
    cve_defs: Optional[List[CVEDefinition]] = None,
) -> Generator[Dict[str, Any], None, Optional[AttackerHistoryResult]]:
    """Reconstructs one attacker IP's footprint from a log file the user has
    already filtered down to that IP (e.g. via an Elastic query scoped to
    source/client IP over up to a year). Answers: how long has this IP been
    present, what else did it touch, and what access does the evidence
    support -- grounded in per-device stats and matched patterns, same as
    phases 1 and 2, so the LLM isn't reasoning from raw text alone."""
    yield _event("ingest", "start", {"log_count": len(raw_logs)})
    entries = normalize_logs(raw_logs)
    yield _event("ingest", "done", {"parsed": len(entries)})

    yield _event("footprint", "start", None)
    footprint = compute_device_footprint(entries)
    first_seen, last_seen = overall_span(entries)
    yield _event("footprint", "done", {
        "devices": footprint,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "device_count": len(footprint),
    })

    if not entries:
        yield _event("synthesize", "error", {"message": "No log entries could be parsed from this file."})
        return None

    # Computed here (not just inline in the prompt below) so it can be sent
    # to the frontend as its own event -- this is what powers the visual
    # swimlane timeline, independent of and before the LLM call.
    yield _event("timeline", "start", None)
    condensed = condense_history(entries)
    yield _event("timeline", "done", {
        "events": condensed,
        "first_seen": first_seen,
        "last_seen": last_seen,
    })

    yield _event("signatures", "start", None)
    matches = match_signatures(entries)
    db_matches = match_cve_database(entries, cve_defs or [])
    matches = matches + db_matches
    yield _event("signatures", "done", {
        "matches": [m.model_dump() for m in matches],
        "cve_database_checked": len(cve_defs or []),
        "cve_database_matched": len(db_matches),
    })

    system_prompt = (
        "You are a security incident analyst. You are given a log history that has already "
        "been filtered by the user to ONE specific attacker/source IP address, potentially "
        "spanning up to a year, across a per-device breakdown, a condensed activity timeline, "
        "and pattern-matched indicators (matched by deterministic rules, not by you). "
        "Answer exactly three questions, grounded ONLY in the evidence given -- never invent "
        "a device, timestamp, or capability not present in the input: "
        "(1) how long has this IP been present in the network, based on the earliest and latest "
        "timestamps seen; (2) what other devices/systems did it touch, and what did it do on "
        "each one; (3) what level of access does the evidence support (e.g. read-only "
        "reconnaissance vs. authenticated user vs. admin/root vs. persistent backdoor), citing "
        "the specific matched patterns (privilege escalation, config tampering, etc.) that "
        "support your assessment -- do not claim a higher access level than the evidence shows. "
        "Only cite a specific CVE if it appears verbatim in the indicators' cve_ids field. "
        "If the history has gaps or the evidence for a question is thin, say so explicitly in "
        "that answer rather than filling the gap with a guess. "
        'Respond ONLY with a JSON object of this exact shape: {"duration_answer": string, '
        '"footprint_answer": string, "access_answer": string, "devices_summary": [string, ...], '
        '"cited_cves": [string, ...], "confidence": number 0-1, "caveats": string}. '
        "Each of the three *_answer fields should be a few sentences, written as a direct answer "
        "to that specific question. devices_summary should be one short line per device touched."
    )

    user_prompt = f"Overall span of this filtered history: {first_seen or 'unknown'} -> {last_seen or 'unknown'}\n\n"
    user_prompt += "Per-device breakdown (sorted by volume of activity):\n"
    for d in footprint:
        user_prompt += (
            f"- device_ip={d['device_ip']} device_name={d['device_name']} "
            f"log_count={d['log_count']} first_seen={d['first_seen']} last_seen={d['last_seen']} "
            f"severity_breakdown={d['severity_breakdown']}\n"
        )

    user_prompt += "\nCondensed activity (repeated near-identical lines collapsed with a count and first/last timestamp):\n"
    for c in condensed:
        if c["count"] > 1:
            user_prompt += f"- [{c['device']}] {c['message']}  (x{c['count']}, {c['first_ts']} -> {c['last_ts']})\n"
        else:
            user_prompt += f"- [{c['device']}] {c['first_ts'] or 'unknown time'}: {c['message']}\n"

    user_prompt += "\nMatched attack-pattern / CVE indicators (ground truth, do not exceed these):\n"
    if matches:
        for m in matches:
            user_prompt += f"- {m.name}: {m.description} | cve_ids={m.cve_ids} | example_lines={m.matched_lines[:3]}\n"
    else:
        user_prompt += "- none matched\n"

    yield _event("synthesize", "start", None)
    try:
        parsed = call_llm_json(system_prompt, user_prompt)
        result = AttackerHistoryResult(**parsed)
    except (LLMError, TypeError, ValueError) as e:
        yield _event("synthesize", "error", {"message": str(e)})
        return None

    yield _event("synthesize", "done", {"result": result.model_dump()})
    return result
