from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Check:
    name: str
    status: str
    details: str
    score_delta: int = 0

@dataclass
class UrlReport:
    original_url: str
    normalized_url: str
    domain: str
    registered_domain: str
    score: int
    risk_level: RiskLevel
    confidence: int
    checks: list[Check] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)