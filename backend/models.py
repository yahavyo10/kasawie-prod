"""
Shared data models for the Sherlog pipeline.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class LogEntry(BaseModel):
    timestamp: Optional[str] = None
    device_ip: Optional[str] = None
    device_name: Optional[str] = None
    message: str = ""
    severity: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class DeviceStats(BaseModel):
    device_ip: str
    device_name: Optional[str] = None
    log_count: int
    error_count: int
    error_rate: float
    distinct_messages: int
    anomaly_score: float
    sample_messages: List[str] = Field(default_factory=list)


class LocalizationResult(BaseModel):
    device_ip: str
    device_name: Optional[str] = None
    offending_message: str
    confidence: float
    reasoning: List[str] = Field(default_factory=list)
    ruled_out: List[str] = Field(default_factory=list)


class SignatureMatch(BaseModel):
    name: str
    description: str
    matched_lines: List[str] = Field(default_factory=list)
    cve_ids: List[str] = Field(default_factory=list)
    product: str = ""


class TimelineEvent(BaseModel):
    timestamp: Optional[str] = None
    window: str
    device_ip: str
    message: str
    tag: Optional[str] = None


class NarrativeResult(BaseModel):
    headline: str
    summary: str
    story_steps: List[str] = Field(default_factory=list)
    cited_cves: List[str] = Field(default_factory=list)
    confidence: float
    caveats: str = ""


class ExposedDevice(BaseModel):
    device_ip: str = ""
    device_name: str = ""


class AffectedSignature(BaseModel):
    """One product signature (vendor/model/firmware/etc.) the LLM judged as
    plausibly affected by a CVE. Expanded back to real devices deterministically
    in code (see inventory_db.group_devices_by_signature) -- the LLM only ever
    reasons about which product signature is affected, never enumerates or
    invents individual devices itself."""
    signature: Dict[str, Any] = Field(default_factory=dict)
    reasoning: str = ""
    device_count: int = 0
    sample_devices: List[ExposedDevice] = Field(default_factory=list)


class CVEExposureResult(BaseModel):
    """One CVE's LLM-driven exposure assessment against the real inventory,
    reasoned about at the product-signature level so this stays cheap and
    accurate regardless of whether the fleet is 6 devices or 6,000."""
    cve_id: str
    cve_summary: str = ""
    affected_signatures: List[AffectedSignature] = Field(default_factory=list)
    total_exposed_devices: int = 0
    confidence: float = 0.0
    caveats: str = ""


class AttackerHistoryResult(BaseModel):
    """Answers the three specific questions a defender asks once an attacker
    IP has been identified: how long, where else, and what access."""
    duration_answer: str    # how long has this IP been present in the network
    footprint_answer: str   # what other devices/systems did it touch
    access_answer: str      # what level of access does the evidence support
    devices_summary: List[str] = Field(default_factory=list)  # short per-device notes
    cited_cves: List[str] = Field(default_factory=list)
    confidence: float
    caveats: str = ""
