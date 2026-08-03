"""
Lightweight, explainable pattern matching over log messages.

The point of this module is to give the phase-2 LLM call *grounded* evidence
to reason over, rather than letting it freely invent CVE numbers. We only ever
extract a CVE ID when one is literally present in a log line (e.g. quoted by
an IDS/IPS alert) -- everything else is described as a *pattern class*
("resembles brute-force activity") rather than a specific vulnerability.
"""
import re
from typing import List
from models import LogEntry, SignatureMatch

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

PATTERNS = [
    {
        "name": "credential_brute_force",
        "description": "Repeated authentication failures consistent with a brute-force or credential-stuffing attempt",
        "regex": re.compile(r"(failed login|authentication failur|invalid credential|login failed|auth.*failed)", re.IGNORECASE),
        "min_hits": 3,
    },
    {
        "name": "privilege_escalation",
        "description": "Indicators of a privilege escalation or unauthorized elevation attempt",
        "regex": re.compile(r"(privilege escalation|unauthorized (role|access|elevation)|elevated to (root|admin)|sudo:.*COMMAND|provisioned with privilege)", re.IGNORECASE),
        "min_hits": 1,
    },
    {
        "name": "port_scan",
        "description": "Pattern consistent with port/service scanning",
        "regex": re.compile(r"(port scan|SYN flood|multiple ports? (probed|scanned))", re.IGNORECASE),
        "min_hits": 1,
    },
    {
        "name": "injection_or_rce_attempt",
        "description": "Strings consistent with command injection, remote code execution, or web exploitation attempts",
        "regex": re.compile(r"(union select|\.\./\.\./|<script|cmd\.exe|wget http|curl http.*\|.*sh|base64 -d|eval\(|command injection)", re.IGNORECASE),
        "min_hits": 1,
    },
    {
        "name": "config_or_firmware_tamper",
        "description": "Configuration or firmware modification outside of a known maintenance window",
        "regex": re.compile(r"(config(uration)? (changed|modified)|firmware (flash|update|write)|unauthorized write|implant file|saved to startup-config)", re.IGNORECASE),
        "min_hits": 1,
    },
]


def extract_cves(text: str) -> List[str]:
    return sorted(set(m.upper() for m in CVE_PATTERN.findall(text)))


def match_signatures(entries: List[LogEntry]) -> List[SignatureMatch]:
    """Scan all log lines for the device's timeline and return matched patterns
    with the literal evidence lines and any explicitly-cited CVE IDs."""
    results: List[SignatureMatch] = []

    for pattern in PATTERNS:
        matched_lines = [e.message for e in entries if e.message and pattern["regex"].search(e.message)]
        if len(matched_lines) >= pattern["min_hits"]:
            cves: List[str] = []
            for line in matched_lines:
                cves.extend(extract_cves(line))
            results.append(
                SignatureMatch(
                    name=pattern["name"],
                    description=pattern["description"],
                    matched_lines=matched_lines[:8],
                    cve_ids=sorted(set(cves)),
                )
            )

    loose_cves = set()
    for e in entries:
        loose_cves.update(extract_cves(e.message))
    already_cited = {c for r in results for c in r.cve_ids}
    extra = loose_cves - already_cited
    if extra:
        results.append(
            SignatureMatch(
                name="explicit_cve_reference",
                description="Log lines that directly cite a CVE identifier",
                matched_lines=[e.message for e in entries if any(c in e.message.upper() for c in extra)][:8],
                cve_ids=sorted(extra),
            )
        )

    return results
