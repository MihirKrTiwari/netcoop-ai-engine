"""
tests/test_timeutils.py
Unit tests for core/timeutils.py: timestamp parsing, epoch vs ISO, and mixed timezone offsets.
"""

from datetime import datetime, timezone
import pytest

from core.schemas import TelemetryMetric
from core.timeutils import is_newer, parse_datetime


class TestTimeUtilsParsing:
    """
    Validates parsing ISO-8601 (with/without Z, arbitrary offsets, naive as UTC)
    and UNIX epoch seconds/milliseconds into aware UTC datetimes.
    """

    def test_parse_iso_with_z(self) -> None:
        dt = parse_datetime("2026-10-31T14:30:00Z")
        assert dt is not None
        assert dt.tzinfo is not None
        assert dt == datetime(2026, 10, 31, 14, 30, 0, tzinfo=timezone.utc)

    def test_parse_iso_naive_treated_as_utc(self) -> None:
        dt = parse_datetime("2026-10-31T14:30:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc
        assert dt == datetime(2026, 10, 31, 14, 30, 0, tzinfo=timezone.utc)

    def test_parse_iso_space_separated_naive(self) -> None:
        dt = parse_datetime("2026-10-31 14:30:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc
        assert dt.hour == 14 and dt.minute == 30

    def test_parse_iso_with_explicit_offset(self) -> None:
        # +05:30 offset: 20:00:00+05:30 is 14:30:00 UTC
        dt = parse_datetime("2026-10-31T20:00:00+05:30")
        assert dt is not None
        assert dt.tzinfo is not None
        assert dt == datetime(2026, 10, 31, 14, 30, 0, tzinfo=timezone.utc)

    def test_parse_iso_with_negative_offset(self) -> None:
        # -04:00 offset: 10:30:00-04:00 is 14:30:00 UTC
        dt = parse_datetime("2026-10-31T10:30:00-04:00")
        assert dt is not None
        assert dt == datetime(2026, 10, 31, 14, 30, 0, tzinfo=timezone.utc)

    def test_parse_epoch_seconds_numeric_and_string(self) -> None:
        # 1793457000 is 2026-10-31 14:30:00 UTC
        dt_int = parse_datetime(1793457000)
        dt_float = parse_datetime(1793457000.0)
        dt_str = parse_datetime("1793457000")

        expected = datetime(2026, 10, 31, 14, 30, 0, tzinfo=timezone.utc)
        assert dt_int == expected
        assert dt_float == expected
        assert dt_str == expected

    def test_parse_epoch_milliseconds_numeric_and_string(self) -> None:
        # 1793457000000 is 2026-10-31 14:30:00 UTC in milliseconds
        dt_ms = parse_datetime(1793457000000)
        dt_ms_str = parse_datetime("1793457000000")

        expected = datetime(2026, 10, 31, 14, 30, 0, tzinfo=timezone.utc)
        assert dt_ms == expected
        assert dt_ms_str == expected

    def test_parse_invalid_or_none(self) -> None:
        assert parse_datetime(None) is None
        assert parse_datetime("") is None
        assert parse_datetime("not-a-timestamp") is None


class TestTimeUtilsChronologicalComparison:
    """
    Validates is_newer with epoch vs ISO, mixed offsets, and TelemetryMetric instances.
    """

    def test_compare_epoch_vs_iso(self) -> None:
        # 1793457300 is 14:35:00 UTC (newer)
        # "2026-10-31T14:30:00Z" is 14:30:00 UTC (older)
        assert is_newer(1793457300, "2026-10-31T14:30:00Z") is True
        assert is_newer("2026-10-31T14:30:00Z", 1793457300) is False

    def test_compare_mixed_offsets(self) -> None:
        # 20:05:00+05:30 -> 14:35:00 UTC (newer)
        # 14:30:00Z      -> 14:30:00 UTC (older)
        newer_ts = "2026-10-31T20:05:00+05:30"
        older_ts = "2026-10-31T14:30:00Z"
        assert is_newer(newer_ts, older_ts) is True
        assert is_newer(older_ts, newer_ts) is False

        # Equivalent times with different offsets: neither is strictly newer
        t1 = "2026-10-31T20:00:00+05:30"
        t2 = "2026-10-31T14:30:00Z"
        assert is_newer(t1, t2) is False
        assert is_newer(t2, t1) is False

    def test_compare_telemetry_metric_objects(self) -> None:
        m_old = TelemetryMetric(
            metric_name="latency",
            value=45.0,
            unit="ms",
            timestamp="2026-10-31T14:30:00Z",
            device_id="dev-01",
        )
        m_new = TelemetryMetric(
            metric_name="latency",
            value=120.0,
            unit="ms",
            timestamp="1793457600000",  # 14:40:00 UTC in ms
            device_id="dev-01",
        )
        assert is_newer(m_new, m_old) is True
        assert is_newer(m_old, m_new) is False

    def test_compare_missing_timestamp_fallbacks(self) -> None:
        m_with_ts = TelemetryMetric(
            metric_name="cpu",
            value=50.0,
            unit="%",
            timestamp="2026-10-31T14:30:00Z",
            device_id="dev-01",
        )
        m_no_ts = TelemetryMetric(
            metric_name="cpu",
            value=60.0,
            unit="%",
            timestamp=None,
            device_id="dev-01",
        )
        assert is_newer(m_with_ts, m_no_ts) is True
        assert is_newer(m_no_ts, m_with_ts) is False
