from __future__ import annotations

import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import parse_qs, urlparse

import idna
import tldextract

from suspicionkit.core.content_probe import inspect_html
from suspicionkit.core.dns_probe import probe_dns
from suspicionkit.core.http_probe import probe_url
from suspicionkit.core.normalizer import normalize_url
from suspicionkit.core.popularity import estimate_popularity
from suspicionkit.core.rules import (
    BRAND_DOMAINS,
    LEGITIMATE_DOMAINS,
    SENSITIVE_PARAMS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    TRACKING_PARAMS,
)
from suspicionkit.core.scoring import clamp_score, confidence_from_checks, level_from_score
from suspicionkit.core.ssl_probe import probe_certificate
from suspicionkit.core.whois_probe import probe_whois
from suspicionkit.models import Check, UrlReport


def analyze_url(
    raw_url: str,
    *,
    no_network: bool = False,
    timeout: float = 7.0,
    inspect_content: bool = True,
) -> UrlReport:
    normalized_url = normalize_url(raw_url)
    parsed = urlparse(normalized_url)
    host = parsed.hostname or ""

    extracted = tldextract.extract(normalized_url)
    registered_domain = extracted.top_domain_under_public_suffix or host
    suffix = extracted.suffix

    checks: list[Check] = []
    warnings: list[str] = []
    notes: list[str] = []
    risk_score = 0

    def add_check(name: str, status: str, details: str, score_delta: int = 0) -> None:
        nonlocal risk_score
        risk_score += score_delta
        checks.append(Check(name=name, status=status, details=details, score_delta=score_delta))

    _run_static_checks(
        add_check=add_check,
        normalized_url=normalized_url,
        parsed=parsed,
        host=host,
        registered_domain=registered_domain,
        suffix=suffix,
        notes=notes,
    )

    if no_network:
        add_check("Network checks", "skipped", "Network checks disabled by --no-network.", 0)
        add_check("WHOIS", "skipped", "WHOIS check disabled by --no-network.", 0)
        add_check("TLS certificate", "skipped", "Certificate check disabled by --no-network.", 0)
        add_check("Content inspection", "skipped", "HTML inspection disabled by --no-network.", 0)
    else:
        _run_dns_checks(add_check, host)
        _run_whois_checks(add_check, registered_domain)

        if parsed.scheme == "https":
            _run_certificate_checks(add_check, host)
        else:
            add_check(
                "TLS certificate",
                "skipped",
                "URL is not HTTPS, certificate was not checked.",
                0,
            )

        http_result = probe_url(
            normalized_url,
            timeout=timeout,
            follow_redirects=True,
            read_body=inspect_content,
        )

        _run_http_checks(add_check, http_result, normalized_url, host)

        if inspect_content and http_result.ok and http_result.html_snippet:
            _run_content_checks(
                add_check,
                http_result.html_snippet,
                http_result.final_url or normalized_url,
            )
        elif inspect_content and http_result.ok:
            add_check("Content inspection", "skipped", "No HTML body was available to inspect.", 0)
        elif inspect_content:
            add_check(
                "Content inspection",
                "skipped",
                "HTTP probe failed, content was not inspected.",
                0,
            )

    warnings.append(
        "No CLI tool can guarantee 99% URL safety. SuspicionKit combines URL, DNS, HTTP, "
        "WHOIS, TLS and basic HTML signals, but advanced phishing pages can still evade checks."
    )
    warnings.append(
        "Any website you contact can usually see your public IP address. Use --no-network "
        "for local-only checks."
    )
    warnings.append(
        "SuspicionKit is not an antivirus, browser sandbox or threat-intelligence database. "
        "Treat the report as an early warning system."
    )

    final_score = clamp_score(risk_score)
    skipped_checks = sum(1 for check in checks if check.status == "skipped")
    failed_network_checks = sum(
        1
        for check in checks
        if check.status in {"warning", "danger"}
        and check.name
        in {"DNS resolution", "WHOIS", "TLS certificate", "HTTP probe", "Content inspection"}
    )
    confidence = confidence_from_checks(len(checks), skipped_checks, failed_network_checks)

    return UrlReport(
        original_url=raw_url,
        normalized_url=normalized_url,
        domain=host,
        registered_domain=registered_domain,
        score=final_score,
        risk_level=level_from_score(final_score),
        evidence_coverage=confidence,
        checks=checks,
        warnings=warnings,
        notes=notes,
    )


def _run_static_checks(
    *,
    add_check,
    normalized_url: str,
    parsed,
    host: str,
    registered_domain: str,
    suffix: str,
    notes: list[str],
) -> None:
    if parsed.scheme == "https":
        add_check("HTTPS", "ok", "URL uses HTTPS.", -5)
    else:
        add_check("HTTPS", "warning", "URL uses HTTP, not HTTPS.", 10)

    try:
        ip = ipaddress.ip_address(host)

        if ip.is_private or ip.is_loopback or ip.is_link_local:
            add_check("IP address host", "danger", "URL points to a private/local IP address.", 28)
        else:
            add_check("IP address host", "warning", "URL uses a raw public IP address.", 20)
    except ValueError:
        add_check("IP address host", "ok", "URL uses a domain name, not a raw IP address.", 0)

    try:
        decoded_host = idna.decode(host.encode("ascii")) if host.startswith("xn--") else host
    except UnicodeError:
        decoded_host = host

    if "xn--" in host or decoded_host != host:
        add_check(
            "Internationalized domain",
            "warning",
            f"Domain may use non-standard characters: {decoded_host}",
            18,
        )
    else:
        add_check("Internationalized domain", "ok", "No punycode detected in domain.", 0)

    if suffix in SUSPICIOUS_TLDS:
        add_check(
            "Top-level domain",
            "warning",
            f"TLD .{suffix} is often abused in suspicious URLs.",
            10,
        )
    else:
        add_check(
            "Top-level domain",
            "ok",
            f"TLD .{suffix or 'unknown'} is not in the local suspicious list.",
            0,
        )

    if registered_domain in SHORTENER_DOMAINS:
        add_check(
            "URL shortener",
            "warning",
            "Domain is a known URL shortener; destination may be hidden.",
            15,
        )
    else:
        add_check("URL shortener", "ok", "Domain is not in the local shortener list.", 0)

    if len(normalized_url) > 180:
        add_check(
            "URL length",
            "warning",
            f"URL is very long: {len(normalized_url)} characters.",
            12,
        )
    elif len(normalized_url) > 120:
        add_check("URL length", "warning", f"URL is long: {len(normalized_url)} characters.", 8)
    else:
        add_check("URL length", "ok", f"URL length is normal: {len(normalized_url)} characters.", 0)

    if "@" in normalized_url:
        add_check("@ symbol", "danger", "URL contains @, which can hide the real destination.", 25)
    else:
        add_check("@ symbol", "ok", "No @ symbol detected.", 0)

    found_keywords = [
        keyword for keyword in sorted(SUSPICIOUS_KEYWORDS) if keyword in normalized_url.lower()
    ]

    if found_keywords:
        add_check(
            "Suspicious keywords",
            "warning",
            "Found suspicious words: " + ", ".join(found_keywords[:10]),
            min(24, len(found_keywords) * 4),
        )
    else:
        add_check("Suspicious keywords", "ok", "No suspicious keywords detected.", 0)

    params = parse_qs(parsed.query)
    tracking_found = []
    sensitive_found = []

    for param_name in params:
        normalized_name = param_name.lower()

        if normalized_name in TRACKING_PARAMS:
            tracking_found.append(param_name)

        if normalized_name in SENSITIVE_PARAMS:
            sensitive_found.append(param_name)

    if tracking_found:
        add_check(
            "Tracking parameters",
            "info",
            "Tracking parameters found: " + ", ".join(tracking_found),
            3,
        )
        notes.append(
            "Tracking parameters do not automatically mean malware, but they can be used "
            "for analytics and attribution."
        )
    else:
        add_check("Tracking parameters", "ok", "No common tracking parameters found.", 0)

    if sensitive_found:
        add_check(
            "Sensitive parameters",
            "warning",
            "Sensitive-looking parameters found: " + ", ".join(sensitive_found),
            min(16, len(sensitive_found) * 8),
        )
    else:
        add_check("Sensitive parameters", "ok", "No sensitive-looking parameters found.", 0)

    brand_warning = _check_brand_impersonation(host, registered_domain)

    if brand_warning:
        add_check("Brand impersonation", "danger", brand_warning, 25)
    else:
        add_check("Brand impersonation", "ok", "No obvious brand impersonation detected.", 0)

    popularity_label, popularity_delta, popularity_details = estimate_popularity(registered_domain)
    add_check("Popularity", popularity_label, popularity_details, popularity_delta)


def _run_dns_checks(add_check, host: str) -> None:
    dns_result = probe_dns(host)

    if not dns_result.ok:
        add_check("DNS resolution", "warning", f"DNS check failed: {dns_result.error}", 10)
        return

    details = f"Resolved to {len(dns_result.addresses)} address(es)."

    if dns_result.name_servers:
        details += f" NS: {', '.join(dns_result.name_servers[:2])}"

    add_check("DNS resolution", "ok", details, 0)

    if dns_result.has_private_ip:
        add_check("DNS private IP", "danger", "DNS returned private/local IP address.", 25)
    else:
        add_check("DNS private IP", "ok", "No private/local IP address detected in DNS.", 0)

    if not dns_result.name_servers:
        add_check("DNS nameservers", "warning", "No NS records were collected.", 4)
    else:
        add_check("DNS nameservers", "ok", f"Found {len(dns_result.name_servers)} NS record(s).", 0)


def _run_whois_checks(add_check, registered_domain: str) -> None:
    whois_result = probe_whois(registered_domain)

    if not whois_result.ok:
        add_check("WHOIS", "warning", f"WHOIS lookup failed: {whois_result.error}", 6)
        return

    if whois_result.age_days is None:
        add_check("Domain age", "unknown", "WHOIS did not return creation date.", 5)
    elif whois_result.age_days < 14:
        add_check(
            "Domain age",
            "danger",
            f"Domain is extremely new: {whois_result.age_days} days.",
            28,
        )
    elif whois_result.age_days < 90:
        add_check("Domain age", "warning", f"Domain is new: {whois_result.age_days} days.", 16)
    elif whois_result.age_days < 365:
        add_check("Domain age", "info", f"Domain age: {whois_result.age_days} days.", 4)
    else:
        add_check("Domain age", "ok", f"Domain age: {whois_result.age_days} days.", -5)

    if whois_result.registrar:
        add_check("Registrar", "info", f"Registrar: {whois_result.registrar}", 0)
    else:
        add_check("Registrar", "unknown", "Registrar was not returned by WHOIS.", 2)

    if whois_result.days_until_expiry is None:
        add_check("Domain expiry", "unknown", "WHOIS did not return expiration date.", 3)
    elif whois_result.days_until_expiry < 0:
        add_check("Domain expiry", "danger", "Domain appears to be expired.", 25)
    elif whois_result.days_until_expiry < 30:
        add_check(
            "Domain expiry",
            "warning",
            f"Domain expires soon: {whois_result.days_until_expiry} days.",
            8,
        )
    else:
        add_check(
            "Domain expiry",
            "ok",
            f"Domain expires in {whois_result.days_until_expiry} days.",
            0,
        )


def _run_certificate_checks(add_check, host: str) -> None:
    cert_result = probe_certificate(host)

    if not cert_result.ok:
        add_check(
            "TLS certificate",
            "warning",
            f"Certificate check failed: {cert_result.error}",
            12,
        )
        return

    if cert_result.days_until_expiry is None:
        add_check(
            "TLS certificate",
            "unknown",
            "Certificate exists, but expiry date was not parsed.",
            3,
        )
    elif cert_result.days_until_expiry < 0:
        add_check("TLS certificate", "danger", "Certificate is expired.", 30)
    elif cert_result.days_until_expiry < 14:
        add_check(
            "TLS certificate",
            "warning",
            f"Certificate expires soon: {cert_result.days_until_expiry} days.",
            10,
        )
    else:
        add_check(
            "TLS certificate",
            "ok",
            f"Certificate is valid for {cert_result.days_until_expiry} more days.",
            -3,
        )

    if cert_result.issuer:
        add_check("TLS issuer", "info", cert_result.issuer, 0)


def _run_http_checks(add_check, http_result, normalized_url: str, original_host: str) -> None:
    if not http_result.ok:
        add_check("HTTP probe", "warning", f"Could not fetch URL: {http_result.error}", 8)
        return

    if http_result.redirects_count > 3:
        add_check(
            "Redirects",
            "warning",
            f"URL redirects {http_result.redirects_count} times to {http_result.final_url}.",
            12,
        )
    elif http_result.redirects_count > 0:
        add_check(
            "Redirects",
            "info",
            f"URL redirects {http_result.redirects_count} time(s) to {http_result.final_url}.",
            3,
        )
    else:
        add_check("Redirects", "ok", "No redirects detected.", 0)

    final_host = urlparse(http_result.final_url or normalized_url).hostname

    if final_host and final_host != original_host:
        add_check(
            "Final host",
            "warning",
            f"Final host differs from original: {original_host} -> {final_host}",
            12,
        )
    else:
        add_check("Final host", "ok", "Final host matches the original host.", 0)

    if http_result.status_code and http_result.status_code >= 500:
        add_check("HTTP status", "warning", f"Server returned HTTP {http_result.status_code}.", 6)
    elif http_result.status_code and http_result.status_code >= 400:
        add_check("HTTP status", "warning", f"Server returned HTTP {http_result.status_code}.", 5)
    else:
        add_check("HTTP status", "ok", f"Server returned HTTP {http_result.status_code}.", 0)

    headers = http_result.headers

    if "content-security-policy" in headers:
        add_check("Security headers", "ok", "Content-Security-Policy header is present.", -2)
    else:
        add_check("Security headers", "info", "Content-Security-Policy header is missing.", 2)

    if http_result.content_type:
        add_check("Content-Type", "info", f"Content-Type: {http_result.content_type}", 0)


def _run_content_checks(add_check, html: str, base_url: str) -> None:
    content_result = inspect_html(html, base_url)

    if not content_result.ok:
        add_check(
            "Content inspection",
            "warning",
            f"HTML inspection failed: {content_result.error}",
            5,
        )
        return

    if content_result.password_forms:
        add_check(
            "Password forms",
            "warning",
            f"Found {content_result.password_forms} password input(s) on the page.",
            14,
        )
    else:
        add_check("Password forms", "ok", "No password inputs found in HTML.", 0)

    if content_result.external_forms:
        add_check(
            "External forms",
            "danger",
            f"Found {content_result.external_forms} form(s) submitting to another host.",
            22,
        )
    else:
        add_check("External forms", "ok", "No external form actions found.", 0)

    if content_result.hidden_inputs > 10:
        add_check(
            "Hidden inputs",
            "info",
            f"Found many hidden inputs: {content_result.hidden_inputs}.",
            3,
        )

    if content_result.iframes > 0:
        add_check("Iframes", "info", f"Found {content_result.iframes} iframe(s).", 3)

    if content_result.suspicious_keywords:
        add_check(
            "Page text signals",
            "warning",
            "Found suspicious page text: "
            + ", ".join(content_result.suspicious_keywords[:8]),
            min(18, len(content_result.suspicious_keywords) * 4),
        )
    else:
        add_check("Page text signals", "ok", "No suspicious text signals found in HTML.", 0)


def _check_brand_impersonation(host: str, registered_domain: str) -> str | None:
    if registered_domain in LEGITIMATE_DOMAINS:
        return None

    compact_host = re.sub(r"[^a-zA-Z0-9]", "", host.lower())

    for real_domain, brand_variants in BRAND_DOMAINS.items():
        real_name = real_domain.split(".")[0]

        if registered_domain == real_domain:
            continue

        for variant in brand_variants:
            compact_variant = re.sub(r"[^a-zA-Z0-9]", "", variant.lower())
            similarity = SequenceMatcher(None, compact_host, compact_variant).ratio()

            if compact_variant in compact_host or similarity > 0.82:
                return f"Domain may imitate {real_domain}: {host}"

        if real_name in compact_host and registered_domain != real_domain:
            return f"Domain contains brand-like word '{real_name}' but is not {real_domain}."

    return None