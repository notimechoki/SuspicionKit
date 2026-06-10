from __future__ import annotations

from urllib.parse import urlparse, urlunparse


def normalize_url(raw_url: str) -> str:
    value = raw_url.strip()

    if not value:
        raise ValueError("URL is empty")
    
    if "://" not in value:
        value = "https://" + value
    
    parsed = urlparse(value)

    if not parsed.netloc:
        raise ValueError("URL does not contain a valid domain")
    
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.strip().lower()
    path = parsed.path or "/"

    return urlunparse((scheme, netloc, path, "", parsed.query, ""))