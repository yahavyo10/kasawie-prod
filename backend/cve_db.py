"""
Cross-references a device's log timeline against a user-supplied CVE database,
so a known vulnerability can be flagged even when the log text never literally
writes out "CVE-XXXX-XXXXX" (the realistic case -- most device logs describe
symptoms like "out-of-bounds write" or "unauthorized role elevation", not CVE
numbers). Matching is deterministic keyword search, not an LLM guess, so every
match can point at the exact indicator string and log line that triggered it.

Expected input JSON shape -- a bare list, or {"cves": [...]}:
[
  {
    "cve_id": "CVE-2024-21762",
    "product": "FortiOS SSL-VPN",              (optional, for display only)
    "description": "Out-of-bounds write in sslvpnd allowing RCE",
    "indicators": ["ssl-vpn", "out-of-bounds write", "sslvpnd"]
  },
  ...
]

A CVE is considered matched if at least `min_indicator_hits` of its indicator
strings appear (case-insensitive substring match) somewhere in the device's
log messages. Default is 1 -- deliberately permissive, since these logs are
short and a single strong indicator (e.g. "out-of-bounds write") is usually
enough signal on its own. Raise it if you want stricter multi-indicator
corroboration before a match counts.
"""
from typing import List, Dict, Any
from pydantic import BaseModel, Field

from models import LogEntry, SignatureMatch


class CVEDefinition(BaseModel):
    cve_id: str
    product: str = ""
    description: str = ""
    indicators: List[str] = Field(default_factory=list)


def parse_cve_database(raw: Any) -> List[CVEDefinition]:
    """Accepts a bare list or {"cves": [...]} and returns validated CVEDefinitions.
    Entries that fail to parse are skipped rather than raising, so one bad
    entry in a hand-edited file doesn't take down the whole feature."""
    items = raw.get("cves", raw) if isinstance(raw, dict) else raw
    defs: List[CVEDefinition] = []
    for item in items or []:
        try:
            defs.append(CVEDefinition(**item))
        except Exception:
            continue
    return defs


def match_cve_database(
    entries: List[LogEntry],
    cve_defs: List[CVEDefinition],
    min_indicator_hits: int = 1,
) -> List[SignatureMatch]:
    """Checks each CVE definition's indicators against the device's log messages.
    Returns one SignatureMatch per CVE that meets the hit threshold, with the
    exact matched log lines and which indicator words triggered the match."""
    if not cve_defs or not entries:
        return []

    messages = [e.message for e in entries if e.message]
    lower_messages = [(m, m.lower()) for m in messages]

    results: List[SignatureMatch] = []
    for cve in cve_defs:
        if not cve.indicators:
            continue
        matched_lines: List[str] = []
        matched_indicators: set = set()
        for indicator in cve.indicators:
            ind_lower = indicator.lower().strip()
            if not ind_lower:
                continue
            for original, lower in lower_messages:
                if ind_lower in lower:
                    matched_indicators.add(indicator)
                    if original not in matched_lines:
                        matched_lines.append(original)

        if len(matched_indicators) >= min_indicator_hits:
            desc = cve.description or "No description provided"
            if cve.product:
                desc = f"[{cve.product}] {desc}"
            desc += f" -- matched on indicator(s): {', '.join(sorted(matched_indicators))}"
            results.append(
                SignatureMatch(
                    name=f"cve_database_match",
                    description=desc,
                    matched_lines=matched_lines[:8],
                    cve_ids=[cve.cve_id],
                )
            )
    return results
