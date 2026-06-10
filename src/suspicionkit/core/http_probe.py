from __future__ import annotations

from dataclasses import dataclass, field

import httpx


@dataclass
class RedirectHop:
    status_code: int
    url: str
    location: str | None = None


@dataclass
class HttpProbeResult:
    ok: bool
    final_url: str | None = None
    status_code: int | None = None
    redirects_count: int = 0
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    error: str | None = None
    server: str | None = None
    content_type: str | None = None
    html_snippet: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


def probe_url(
    url: str,
    timeout: float = 7.0,
    follow_redirects: bool = True,
    read_body: bool = True,
    max_body_chars: int = 120_000,
) -> HttpProbeResult:
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=follow_redirects,
            headers={"User-Agent": "SuspicionKit/0.0.2"},
        ) as client:
            response = client.get(url)

        content_type = response.headers.get("content-type", "")
        html_snippet = None

        if read_body and "text/html" in content_type.lower():
            html_snippet = response.text[:max_body_chars]

        redirect_chain = []

        for item in response.history:
            redirect_chain.append(
                RedirectHop(
                    status_code=item.status_code,
                    url=str(item.url),
                    location=item.headers.get("location"),
                )
            )

        return HttpProbeResult(
            ok=True,
            final_url=str(response.url),
            status_code=response.status_code,
            redirects_count=len(response.history),
            redirect_chain=redirect_chain,
            server=response.headers.get("server"),
            content_type=content_type or None,
            html_snippet=html_snippet,
            headers={key.lower(): value for key, value in response.headers.items()},
        )

    except httpx.HTTPError as exc:
        return HttpProbeResult(ok=False, error=str(exc))