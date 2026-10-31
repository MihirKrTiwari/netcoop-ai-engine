"""
core/timeutils.py
Robust timestamp parsing and chronological comparison utilities for NetCoop AI.
Handles ISO-8601 strings (with/without Z, arbitrary offsets, naive treated as UTC)
and UNIX epoch timestamps (seconds and milliseconds) into timezone-aware UTC datetimes.
"""

from datetime import datetime, timezone
import re
from typing import Any, Optional, Union


# ISO 8601 regex pattern to detect ISO-like strings
_ISO_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"
)

# Epoch millisecond threshold: timestamps >= 10^11 are milliseconds (covers years 1973 to 5138)
_EPOCH_MS_THRESHOLD = 1e11


def parse_datetime(val: Any) -> Optional[datetime]:
    """
    Parse an arbitrary timestamp representation into a timezone-aware UTC datetime.

    Supported inputs:
    - datetime: aware datetimes converted to UTC; naive datetimes assumed to be UTC.
    - ISO-8601 string:
        - "2026-10-31T14:30:00Z" (UTC trailing Z)
        - "2026-10-31T14:30:00+05:30" (explicit offset)
        - "2026-10-31T14:30:00-04:00"
        - "2026-10-31T14:30:00" (naive ISO, treated as UTC)
        - "2026-10-31 14:30:00.123456" (space-separated, fractional seconds)
    - Epoch numeric (int or float) or numeric string:
        - Epoch seconds (e.g. 1793457000 or 1793457000.5)
        - Epoch milliseconds (e.g. 1793457000123)

    Returns:
        Timezone-aware datetime in UTC, or None if input cannot be parsed.
    """
    if val is None:
        return None

    # 1. Already a datetime instance
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)

    # 2. Numeric epoch (int or float)
    if isinstance(val, (int, float)):
        try:
            sec = float(val) / 1000.0 if abs(val) >= _EPOCH_MS_THRESHOLD else float(val)
            return datetime.fromtimestamp(sec, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None

    # 3. String representations
    if isinstance(val, str):
        clean = val.strip()
        if not clean:
            return None

        # Check for numeric epoch string (e.g. "1793457000" or "1793457000123")
        try:
            num = float(clean)
            sec = num / 1000.0 if abs(num) >= _EPOCH_MS_THRESHOLD else num
            return datetime.fromtimestamp(sec, tz=timezone.utc)
        except ValueError:
            pass

        # Parse ISO-8601 format
        # Normalize trailing 'Z' to '+00:00' for fromisoformat compatibility across Python versions
        iso_str = clean.replace(" ", "T")
        if iso_str.endswith("Z"):
            iso_str = iso_str[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

    return None


def is_newer(new_sample: Any, current_sample: Any) -> bool:
    """
    Compare two timestamp values or metric objects chronologically.
    Accepts TelemetryMetric objects, datetime objects, strings, or numeric epochs.

    Returns True if new_sample is strictly newer than current_sample.
    If timestamps are missing, prefers an available timestamp over None.
    Falls back safely to lexicographical comparison if unparseable.
    """
    new_ts = getattr(new_sample, "timestamp", new_sample)
    curr_ts = getattr(current_sample, "timestamp", current_sample)

    if new_ts is not None and curr_ts is None:
        return True
    if new_ts is None and curr_ts is not None:
        return False
    if new_ts is None and curr_ts is None:
        return False

    dt_new = parse_datetime(new_ts)
    dt_curr = parse_datetime(curr_ts)

    if dt_new is not None and dt_curr is not None:
        return dt_new > dt_curr
    if dt_new is not None and dt_curr is None:
        return True
    if dt_new is None and dt_curr is not None:
        return False

    return str(new_ts) > str(curr_ts)
