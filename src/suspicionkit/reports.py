from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from suspicionkit import __version__
from suspicionkit.models import Check, UrlReport


def report_to_dict(report: UrlReport) -> dict[str, Any]:
    return {
        "tool": "SuspicionKit",
        "version": __version__,
        "target": report.original_url,
        "normalized_url": report.normalized_url,
        "domain": report.domain,
        "root_domain": report.registered_domain,
        "score": report.score,
        "risk_level": report.risk_level.value,
        "evidence_coverage": report.evidence_coverage,
        "checks": [_check_to_dict(check) for check in report.checks],
        "notes": report.notes,
        "warnings": report.warnings,
    }


def report_to_json(report: UrlReport, *, pretty: bool = True) -> str:
    indent = 2 if pretty else None
    return json.dumps(report_to_dict(report), ensure_ascii=False, indent=indent)


def write_text_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _check_to_dict(check: Check) -> dict[str, Any]:
    return {
        "id": _slugify(check.name),
        "name": check.name,
        "status": check.status,
        "details": check.details,
        "score_delta": check.score_delta,
    }


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return slug or "check"