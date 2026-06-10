from datetime import UTC, date, datetime

from suspicionkit.core.whois_probe import _first_datetime


def test_first_datetime_from_datetime():
    value = datetime(2024, 1, 1, 10, 30)

    result = _first_datetime(value)

    assert result == datetime(2024, 1, 1, 10, 30, tzinfo=UTC)


def test_first_datetime_from_list():
    value = [None, datetime(2024, 1, 1)]

    result = _first_datetime(value)

    assert result == datetime(2024, 1, 1, tzinfo=UTC)


def test_first_datetime_from_date():
    value = date(2024, 1, 1)

    result = _first_datetime(value)

    assert result == datetime(2024, 1, 1, tzinfo=UTC)