from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from suspicionkit.core.rules import SUSPICIOUS_CONTENT_KEYWORDS


@dataclass
class ContentProbeResult:
    ok: bool
    title: str | None = None
    password_forms: int = 0
    external_forms: int = 0
    hidden_inputs: int = 0
    iframes: int = 0
    suspicious_keywords: list[str] = field(default_factory=list)
    error: str | None = None


def inspect_html(html: str, base_url: str) -> ContentProbeResult:
    try:
        from bs4 import BeautifulSoup
    except Exception as exc:
        return ContentProbeResult(ok=False, error=f"beautifulsoup4 is not available: {exc}")

    try:
        soup = BeautifulSoup(html, "html.parser")

        title = None
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        password_forms = 0
        external_forms = 0
        hidden_inputs = 0

        base_host = urlparse(base_url).hostname

        for form in soup.find_all("form"):
            inputs = form.find_all("input")

            for input_tag in inputs:
                input_type = str(input_tag.get("type", "")).lower()

                if input_type == "password":
                    password_forms += 1

                if input_type == "hidden":
                    hidden_inputs += 1

            action = form.get("action")
            if action:
                action_url = urljoin(base_url, str(action))
                action_host = urlparse(action_url).hostname

                if action_host and base_host and action_host != base_host:
                    external_forms += 1

        text = soup.get_text(" ", strip=True).lower()
        found_keywords = []

        for keyword in sorted(SUSPICIOUS_CONTENT_KEYWORDS):
            if keyword in text:
                found_keywords.append(keyword)

        return ContentProbeResult(
            ok=True,
            title=title,
            password_forms=password_forms,
            external_forms=external_forms,
            hidden_inputs=hidden_inputs,
            iframes=len(soup.find_all("iframe")),
            suspicious_keywords=found_keywords,
        )

    except Exception as exc:
        return ContentProbeResult(ok=False, error=str(exc))