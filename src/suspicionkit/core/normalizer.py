from __future__ import annotations

from urllib.parse import urlparse, urlunparse

SUPPORTED_SCHEMES = {"http", "https"}
UNSUPPORTED_SCHEME_PREFIXES = {"javascript", "data", "file", "ftp", "mailto"}


def normalize_url(raw_url: str) -> str:
    value = raw_url.strip()

    if not value:
        raise ValueError("URL is empty")

    if "://" not in value:
        scheme_candidate = value.split(":", 1)[0].lower() if ":" in value else ""

        if scheme_candidate in UNSUPPORTED_SCHEME_PREFIXES:
            raise ValueError("Only HTTP and HTTPS URLs are supported")

        value = "https://" + value

    parsed = urlparse(value)

    if not parsed.netloc:
        raise ValueError("URL does not contain a valid domain")

    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    netloc = parsed.netloc.strip().lower()
    path = parsed.path or "/"

    return urlunparse((scheme, netloc, path, "", parsed.query, ""))