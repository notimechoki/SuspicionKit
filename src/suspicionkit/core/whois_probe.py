from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime


@dataclass
class WhoisProbeResult:
    ok: bool
    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    age_days: int | None = None
    days_until_expiry: int | None = None
    error: str | None = None


def probe_whois(domain: str) -> WhoisProbeResult:
    try:
        import whois
    except Exception as exc:
        return WhoisProbeResult(ok=False, error=f"python-whois is not available: {exc}")

    try:
        data = whois.whois(domain)

        creation_date = _first_datetime(data.get("creation_date"))
        expiration_date = _first_datetime(data.get("expiration_date"))
        updated_date = _first_datetime(data.get("updated_date"))

        age_days = None
        if creation_date:
            age_days = (datetime.now(UTC) - creation_date).days

        days_until_expiry = None
        if expiration_date:
            days_until_expiry = (expiration_date - datetime.now(UTC)).days

        registrar = data.get("registrar")
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None

        return WhoisProbeResult(
            ok=True,
            registrar=registrar,
            creation_date=creation_date,
            expiration_date=expiration_date,
            updated_date=updated_date,
            age_days=age_days,
            days_until_expiry=days_until_expiry,
        )

    except Exception as exc:
        return WhoisProbeResult(ok=False, error=str(exc))


def _first_datetime(value: object) -> datetime | None:
    if value is None:
        return None

    if isinstance(value, list):
        for item in value:
            parsed = _first_datetime(item)
            if parsed:
                return parsed
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)

    return None