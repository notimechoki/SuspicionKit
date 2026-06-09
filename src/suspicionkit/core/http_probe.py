from __future__ import annotations

from dataclasses import dataclass

import httpx

@dataclass
class HttpProbeResult:
    ok: bool
    final_url: str | None = None
    status_code: int | None = None
    redirects_count: int = 0
    error: str | None = None
    server: str | None = None
    content_type: str | None = None


def probe_url(url: str, timeout: float = 5.0, follow_redirects: bool = True) -> HttpProbeResult:
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=follow_redirects,
            headers={"User-Agent": "SuspicionKit/0.0.1"},
        ) as client:
            response = client.get(url)
        
        return HttpProbeResult(
            ok=True,
            final_url=str(response.url),
            status_code=response.status_code,
            redirects_count=len(response.history),
            server=response.headers.get("server"),
            content_type=response.headers.get("content-type"),
        )
    
    except httpx.HTTPError as exc:
        return HttpProbeResult(ok=False, error=str(exc))