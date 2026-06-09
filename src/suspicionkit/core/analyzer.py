from __future__ import annotations

import ipaddress
import re
import socket
from difflib import SequenceMatcher
from urllib.parse import parse_qs, urlparse

import dns.resolver
import idna
import tldextract

from suspicionkit.core.http_probe import probe_url
from suspicionkit.core.normalizer import normalize_url
from suspicionkit.core.popularity import estimate_popularity
from suspicionkit.core.rules import (
    BRAND_DOMAINS,
    SENSITIVE_PARAMS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    TRACKING_PARAMS,
)
from suspicionkit.core.scoring import clamp_score, level_from_score
from suspicionkit.models import Check, UrlReport


def analyze_url(raw_url: str, *, no_network: bool = False) -> UrlReport:
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
        checks.append(
            Check(
                name=name,
                status=status,
                details=details,
                score_delta=score_delta,
            )
        )

    if parsed.scheme == "https":
        add_check("HTTPS", "ok", "URL uses HTTPS.", -5)
    else:
        add_check("HTTPS", "warning", "URL does not use HTTPS.", 18)

    try:
        ipaddress.ip_address(host)
        add_check("IP address host", "warning", "URL uses an IP address instead of a domain.", 20)
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

    if len(normalized_url) > 140:
        add_check("URL length", "warning", f"URL is long: {len(normalized_url)} characters.", 8)
    else:
        add_check("URL length", "ok", f"URL length is normal: {len(normalized_url)} characters.", 0)

    if "@" in normalized_url:
        add_check("@ symbol", "danger", "URL contains @, which can hide the real destination.", 25)
    else:
        add_check("@ symbol", "ok", "No @ symbol detected.", 0)

    lower_url = normalized_url.lower()
    found_keywords = []

    for keyword in sorted(SUSPICIOUS_KEYWORDS):
        if keyword in lower_url:
            found_keywords.append(keyword)

    if found_keywords:
        add_check(
            "Suspicious keywords",
            "warning",
            "Found sensitive words: " + ", ".join(found_keywords[:8]),
            min(20, len(found_keywords) * 4),
        )
    else:
        add_check("Suspicious keywords", "ok", "No sensitive keywords detected.", 0)

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
            "Tracking parameters do not automatically mean malware, "
            "but they can be used for analytics and attribution."
        )
    else:
        add_check("Tracking parameters", "ok", "No common tracking parameters found.", 0)

    if sensitive_found:
        add_check(
            "Sensitive parameters",
            "warning",
            "Sensitive-looking parameters found: " + ", ".join(sensitive_found),
            15,
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

    if no_network:
        add_check("Network checks", "skipped", "Network checks disabled by --no-network.", 0)
    else:
        dns_status, dns_details, dns_delta = _dns_check(host)
        add_check("DNS resolution", dns_status, dns_details, dns_delta)

        http_result = probe_url(normalized_url)

        if http_result.ok:
            if http_result.redirects_count > 2:
                add_check(
                    "Redirects",
                    "warning",
                    f"URL redirects {http_result.redirects_count} times to {http_result.final_url}.",
                    10,
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

            if http_result.status_code and http_result.status_code >= 400:
                add_check(
                    "HTTP status",
                    "warning",
                    f"Server returned HTTP {http_result.status_code}.",
                    5,
                )
            else:
                add_check(
                    "HTTP status",
                    "ok",
                    f"Server returned HTTP {http_result.status_code}.",
                    0,
                )
        else:
            add_check("HTTP probe", "warning", f"Could not fetch URL: {http_result.error}", 8)

    warnings.append(
        "Any website you open can usually see your public IP address. "
        "SuspicionKit does not open the page in a browser, but network checks still contact "
        "the host. Use --no-network for offline checks."
    )

    warnings.append(
        "SuspicionKit is not an antivirus and cannot guarantee that a URL is safe. "
        "Treat the report as an early warning system."
    )

    final_score = clamp_score(risk_score)

    return UrlReport(
        original_url=raw_url,
        normalized_url=normalized_url,
        domain=host,
        registered_domain=registered_domain,
        score=final_score,
        risk_level=level_from_score(final_score),
        checks=checks,
        warnings=warnings,
        notes=notes,
    )


def _dns_check(host: str) -> tuple[str, str, int]:
    try:
        socket.gethostbyname(host)
        dns.resolver.resolve(host, "A", lifetime=3)
        return "ok", "Domain resolves successfully.", 0

    except Exception as exc:
        return "warning", f"DNS check failed: {exc}", 10


def _check_brand_impersonation(host: str, registered_domain: str) -> str | None:
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