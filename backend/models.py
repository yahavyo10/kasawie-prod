"""
Shared data models for the netwatch pipeline.
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
