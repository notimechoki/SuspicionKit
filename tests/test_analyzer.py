from suspicionkit.core.analyzer import analyze_url


def test_popular_https_domain_gets_low_score_offline():
    report = analyze_url("https://github.com", no_network=True)

    assert report.registered_domain == "github.com"
    assert report.score <= 25
    assert report.confidence < 100


def test_suspicious_url_gets_higher_score_offline():
    report = analyze_url("http://paypal-login-security.xyz/verify?token=123", no_network=True)

    assert report.score > 40
    assert report.risk_level.value in {"medium", "high", "critical"}


def test_private_ip_is_high_risk_offline():
    report = analyze_url("http://127.0.0.1/admin/login", no_network=True)

    assert report.score >= 40
    assert any(
        check.name == "IP address host" and check.status == "danger"
        for check in report.checks
    )