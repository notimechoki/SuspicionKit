from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class CertificateProbeResult:
    ok: bool
    issuer: str | None = None
    subject: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_until_expiry: int | None = None
    error: str | None = None


def probe_certificate(host: str, port: int = 443, timeout: float = 5.0) -> CertificateProbeResult:
    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()

        not_before = _parse_cert_time(cert.get("notBefore"))
        not_after = _parse_cert_time(cert.get("notAfter"))

        days_until_expiry = None
        if not_after:
            days_until_expiry = (not_after - datetime.now(UTC)).days

        return CertificateProbeResult(
            ok=True,
            issuer=_format_name(cert.get("issuer", ())),
            subject=_format_name(cert.get("subject", ())),
            not_before=not_before,
            not_after=not_after,
            days_until_expiry=days_until_expiry,
        )

    except Exception as exc:
        return CertificateProbeResult(ok=False, error=str(exc))


def _parse_cert_time(value: str | None) -> datetime | None:
    if not value:
        return None

    parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    return parsed.replace(tzinfo=UTC)


def _format_name(parts: tuple) -> str:
    values = []

    for group in parts:
        for key, value in group:
            if key in {"commonName", "organizationName", "countryName"}:
                values.append(f"{key}={value}")

    return ", ".join(values)