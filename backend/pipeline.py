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
import inventory_db
from llm_client import call_llm_json, LLMError, FAST_MODEL
from models import LocalizationResult, TimelineEvent, NarrativeResult, AttackerHistoryResult, CVEExposureResult, ExposedDevice, AffectedSignature


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


def run_llm_exposure_scan(
    cve_ids: List[str],
    root_cause_ip: str,
    root_cause_name: Optional[str],
    db_config: Optional[Dict[str, Any]],
    exclude_ips=None,
) -> tuple:
    """Given the CVE ID(s) actually pinpointed for this incident (from phase 1's
    root cause + phase 2's narrative) and an optional Postgres inventory config,
    fetches the full real inventory, groups it by product SIGNATURE (vendor/
    model/firmware/etc. -- see inventory_db.group_devices_by_signature), and
    asks the LLM which signatures could plausibly be affected by each CVE,
    using the model's own knowledge of what that CVE affects.

    Reasoning happens at the signature level, not per-device, which is what
    keeps this cheap and accurate regardless of fleet size -- a real
    inventory might have thousands of devices but only a few dozen distinct
    product signatures (confirmed against a real 4,500-device inventory:
    the naive per-device approach needed ~360,000 tokens in one call --
    about 45x a typical free-tier budget -- grouping brought that to ~1,700).
    The LLM only ever names which signature INDEX (from a numbered list we
    give it) is affected; expansion back to real devices happens
    deterministically in code, so the model can never invent a device that
    isn't actually in the inventory.

    exclude_ips can be a single IP or a list (phase 3 excludes every device
    the attacker already touched). Returns
    (results: List[CVEExposureResult-as-dict], error_message)."""
    if not db_config or not cve_ids:
        return [], None
    if isinstance(exclude_ips, str):
        exclude_ips = [exclude_ips]
    exclude_set = {str(ip) for ip in (exclude_ips or [])} | {str(root_cause_ip)}

    try:
        all_devices = inventory_db.fetch_all_devices(db_config)
    except inventory_db.InventoryError as e:
        return [], str(e)

    if not all_devices:
        return [], None

    # Exclude already-known devices BEFORE grouping (schema-agnostic: check
    # every column's value, since we don't reliably know which one holds the
    # IP for an arbitrary table) so they can never appear in a count or sample.
    devices = [d for d in all_devices if not any(str(v) in exclude_set for v in d.values())]

    groups = inventory_db.group_devices_by_signature(devices)
    if not groups:
        return [], None

    system_prompt = (
        "You are a security analyst doing an exposure assessment. You are given one or "
        "more CVE IDs already confirmed relevant to a specific incident (identified by an "
        "earlier root-cause localization and causal narrative), the identity of the device "
        "already known to be affected, and a NUMBERED LIST of distinct product signatures "
        "(vendor/model/firmware/etc.) present in a real network inventory -- each signature "
        "represents potentially many individual devices, already deduplicated. "
        "For EACH CVE, use your own knowledge of what software/hardware/vendor that CVE "
        "affects to determine which signature NUMBERS could plausibly also be affected. "
        "This is a best-effort assessment based on your training data about these CVEs -- "
        "it is NOT a substitute for the vendor's official advisory or a real vulnerability "
        "scanner, and every cve entry's caveats field must say so explicitly. "
        "If you do not have reliable knowledge of what a given CVE affects, say so plainly "
        "in that CVE's caveats and return an empty list of affected indices for it rather "
        "than guessing. Only reference signature numbers that are literally in the list given. "
        'Respond ONLY with a JSON object of this exact shape: {"per_cve": [{"cve_id": string, '
        '"cve_summary": string, "affected_indices": [{"index": integer, "reasoning": string}, ...], '
        '"confidence": number 0-1, "caveats": string}, ...]}. '
        "cve_summary should be one sentence on what the CVE actually affects. reasoning should "
        "be a short phrase per signature (e.g. 'same vendor and IOS XE train')."
    )
    user_prompt = (
        f"CVE(s) to assess: {', '.join(cve_ids)}\n"
        f"Already-known affected device: {root_cause_ip} ({root_cause_name or 'unnamed'}) -- "
        f"already excluded from the inventory below.\n\n"
        f"Distinct product signatures in inventory ({len(groups)} total, {len(devices)} devices):\n"
    )
    for i, g in enumerate(groups):
        user_prompt += f"{i}: {g['signature']} (count={g['count']})\n"

    try:
        parsed = call_llm_json(system_prompt, user_prompt)
        per_cve = parsed.get("per_cve", [])
        results = []
        for entry in per_cve:
            affected_sigs = []
            total = 0
            for item in entry.get("affected_indices", []):
                idx = item.get("index")
                if not isinstance(idx, int) or idx < 0 or idx >= len(groups):
                    continue  # LLM referenced a signature that doesn't exist -- skip, don't guess
                g = groups[idx]
                affected_sigs.append(AffectedSignature(
                    signature=g["signature"],
                    reasoning=item.get("reasoning", ""),
                    device_count=g["count"],
                    sample_devices=[
                        ExposedDevice(device_ip=str(s.get("ip") or ""), device_name=str(s.get("name") or ""))
                        for s in g["sample_devices"]
                    ],
                ))
                total += g["count"]
            result = CVEExposureResult(
                cve_id=entry.get("cve_id", ""),
                cve_summary=entry.get("cve_summary", ""),
                affected_signatures=affected_sigs,
                total_exposed_devices=total,
                confidence=entry.get("confidence", 0.0),
                caveats=entry.get("caveats", ""),
            )
            results.append(result.model_dump())
        return results, None
    except (LLMError, TypeError, ValueError) as e:
        return [], str(e)


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
    db_config: Optional[Dict[str, Any]] = None,
) -> Generator[Dict[str, Any], None, Optional[NarrativeResult]]:
    """Build a grounded causal narrative from the 2 windows preceding the anomaly.
    cve_defs, if provided, is checked against the device's timeline via keyword
    indicators -- this can surface a known CVE even when the log text never
    literally writes out the CVE number (see cve_db.py). db_config, if provided,
    triggers an exposure scan (see run_llm_exposure_scan) against the user's own
    Postgres device inventory for whatever CVE(s) this incident pinpoints."""
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

    # Exposure scan runs AFTER the narrative, keyed on the CVE(s) the narrative
    # actually cited -- that's "the CVE used by the attacker" for this incident,
    # grounded by phase 1's root cause + phase 2's narrative, not just anything
    # that happened to pattern-match earlier in the pipeline.
    if db_config and result.cited_cves:
        yield _event("exposure_scan", "start", None)
        exposure_results, exposure_error = run_llm_exposure_scan(
            result.cited_cves, device_ip, root_cause.device_name, db_config, exclude_ips=device_ip
        )
        if exposure_error:
            yield _event("exposure_scan", "error", {"message": exposure_error})
        else:
            yield _event("exposure_scan", "done", {"results": exposure_results})

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

    condensed = condense_history(entries)
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
