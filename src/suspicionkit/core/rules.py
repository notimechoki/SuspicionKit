from __future__ import annotations

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "country",
    "kim",
    "gq",
    "tk",
    "ml",
    "cf",
    "work",
    "rest",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
}

POPULAR_DOMAINS = {
    "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "reddit.com",
    "wikipedia.org",
    "x.com",
    "twitter.com",
    "linkedin.com",
    "paypal.com",
    "netflix.com",
    "openai.com",
    "cloudflare.com",
}

BRAND_DOMAINS = {
    "google.com": ["google", "g00gle", "googIe"],
    "github.com": ["github", "githab", "gitlab"],
    "paypal.com": ["paypal", "paypaI", "pay-pal"],
    "microsoft.com": ["microsoft", "micros0ft"],
    "apple.com": ["apple", "appIe"],
    "instagram.com": ["instagram", "instagrarn"],
    "facebook.com": ["facebook", "facebo0k"],
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "password",
    "passwd",
    "reset",
    "token",
    "session",
    "auth",
    "account",
    "bank",
    "wallet",
    "invoice",
    "payment",
    "confirm",
    "secure",
    "security",
    "update",
}

TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "yclid",
    "mc_cid",
    "mc_eid",
}

SENSITIVE_PARAMS = {
    "token",
    "access_token",
    "auth",
    "session",
    "sid",
    "password",
    "pass",
    "email",
    "phone",
    "redirect",
    "return",
    "next",
    "continue",
}