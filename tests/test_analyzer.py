from suspicionkit.core.analyzer import analyze_url


def test_popular_https_domain_gets_low_score_offline():
    report = analyze_url("https://github.com", no_network=True)

    assert report.registered_domain == "github.com"
    assert report.score <= 25
    assert report.evidence_coverage < 100


def test_suspicious_url_gets_higher_score_offline():
    report = analyze_url("http://paypal-login-security.xyz/verify?token=123", no_network=True)

    assert report.score > 40
    assert report.risk_level.value in {"medium", "high", "critical"}


def test_private_ip_is_high_risk_offline():
    report = analyze_url("http://127.0.0.1/admin/login", no_network=True)

    assert report.score >= 40
    assert any(
        check.name == "IP address host" and check.status == "danger" for check in report.checks
    )


def test_gitlab_is_not_flagged_as_github_impersonation():
    report = analyze_url("https://gitlab.com", no_network=True)

    assert report.registered_domain == "gitlab.com"
    assert not any(
        check.name == "Brand impersonation" and check.status == "danger"
        for check in report.checks
    )


def test_delivery_tracking_url_has_expected_static_signals():
    report = analyze_url("http://delivery-track-support.top/track?token=123", no_network=True)

    assert report.score >= 30
    assert any(check.name == "HTTPS" and check.status == "warning" for check in report.checks)
    assert any(
        check.name == "Top-level domain" and check.status == "warning"
        for check in report.checks
    )
    assert any(check.name == "Sensitive parameters" for check in report.checks)