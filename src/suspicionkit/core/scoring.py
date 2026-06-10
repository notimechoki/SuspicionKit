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


def confidence_from_checks(
    total_checks: int,
    skipped_checks: int,
    failed_network_checks: int,
) -> int:
    if total_checks <= 0:
        return 0

    confidence = 100
    confidence -= skipped_checks * 12
    confidence -= failed_network_checks * 6

    if confidence < 20:
        return 20

    if confidence > 100:
        return 100

    return confidence