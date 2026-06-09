from __future__ import annotations

from suspicionkit.core.rules import POPULAR_DOMAINS


def estimate_popularity(registered_domain: str) -> tuple[str, int, str]:
    if registered_domain in POPULAR_DOMAINS:
        return "popular", -10, "Domain is in the built-in popular domains list."

    return "unknown", 5, "Domain popularity is unknown in local v0.0.1 checks."