from __future__ import annotations

from suspicionkit.models import RiskLevel

def clamp_score(score: int) -> int:
    if score < 0:
        return 0
    
    if score > 100:
        return 100
    
    return score

def level_from_score(score: int) -> RiskLevel:
    if score <= 25:
        return RiskLevel.LOW
    
    if score <= 55:
        return RiskLevel.MEDIUM
    
    if score <= 80:
        return RiskLevel.HIGH
    
    return RiskLevel.CRITICAL