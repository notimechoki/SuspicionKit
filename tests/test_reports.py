import json

from suspicionkit.core.analyzer import analyze_url
from suspicionkit.reports import report_to_dict, report_to_json


def test_report_to_dict_contains_stable_fields():
    report = analyze_url("https://github.com", no_network=True)
    data = report_to_dict(report)

    assert data["tool"] == "SuspicionKit"
    assert data["target"] == "https://github.com"
    assert data["root_domain"] == "github.com"
    assert data["risk_level"] == report.risk_level.value
    assert "evidence_coverage" in data
    assert "confidence" not in data
    assert isinstance(data["checks"], list)
    assert data["checks"]


def test_report_to_json_returns_valid_json():
    report = analyze_url("https://github.com", no_network=True)

    data = json.loads(report_to_json(report))

    assert data["target"] == "https://github.com"
    assert data["checks"][0]["id"]