import pytest

from suspicionkit.core.normalizer import normalize_url


def test_normalize_adds_https():
    assert normalize_url("example.com") == "https://example.com/"


def test_normalize_keeps_query():
    assert normalize_url("https://example.com/a?x=1") == "https://example.com/a?x=1"


def test_empty_url_fails():
    with pytest.raises(ValueError):
        normalize_url("   ")