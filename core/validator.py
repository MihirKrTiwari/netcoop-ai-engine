"""
core/validator.py
Ingestion sanitizer and normalizer for network telemetry payloads in NetCoop AI.
"""

import logging
import math
from typing import Any, Dict, List, Optional, Tuple

from core.schemas import RawTelemetryPayload, TelemetryMetric

logger = logging.getLogger(__name__)

# Unit normalization mappings
_SECONDS_UNITS = frozenset({"s", "sec", "secs", "second", "seconds"})
_MILLISECONDS_UNITS = frozenset({"ms", "msec", "msecs", "millisecond", "milliseconds"})
_MICROSECONDS_UNITS = frozenset({"us", "µs", "usec", "microsecond", "microseconds"})
_NANOSECONDS_UNITS = frozenset({"ns", "nsec", "nanosecond", "nanoseconds"})
_PERCENT_UNITS = frozenset({"%", "pct", "percent", "percentage"})
_RATIO_UNITS = frozenset({"ratio", "fraction"})


def _parse_float(val: Any) -> Optional[float]:
    """
    Safely parse raw value into a finite float.
    Rejects booleans, None, NaNs, infinities, and unparseable strings.
    """
    if isinstance(val, bool) or val is None:
        return None

    try:
        if isinstance(val, (int, float)):
            num = float(val)
        elif isinstance(val, str):
            cleaned = val.strip().replace(",", "")
            if not cleaned:
                return None
            num = float(cleaned)
        else:
            return None

        if math.isnan(num) or math.isinf(num):
            return None
        return num
    except (ValueError, TypeError):
        return None


def _normalize_metric_unit_and_value(metric_name: str, value: float, raw_unit: Any) -> Tuple[float, str]:
    """
    Normalize metric unit variations and convert units to canonical network standards.
    Specifically converts latency in seconds/microseconds to milliseconds and ratios to percentages.
    """
    unit_str = str(raw_unit).strip() if raw_unit is not None else ""
    norm_unit = unit_str.lower()

    if norm_unit in _SECONDS_UNITS:
        return (value * 1000.0, "ms")
    elif norm_unit in _MICROSECONDS_UNITS:
        return (value / 1000.0, "ms")
    elif norm_unit in _NANOSECONDS_UNITS:
        return (value / 1_000_000.0, "ms")
    elif norm_unit in _MILLISECONDS_UNITS:
        return (value, "ms")
    elif norm_unit in _RATIO_UNITS:
        return (value * 100.0, "%")
    elif norm_unit in _PERCENT_UNITS:
        return (value, "%")
    elif norm_unit in {"bps", "bits/s", "bit/s"}:
        return (value, "bps")
    elif norm_unit in {"kbps", "kbit/s", "kbits/s"}:
        return (value, "Kbps")
    elif norm_unit in {"mbps", "mbit/s", "mb/s", "mbits/s"}:
        return (value, "Mbps")
    elif norm_unit in {"gbps", "gbit/s", "gb/s", "gbits/s"}:
        return (value, "Gbps")
    elif norm_unit in {"pps", "packets/s", "pkt/s"}:
        return (value, "pps")

    fallback_unit = unit_str if unit_str else "dimensionless"
    return (value, fallback_unit)


def validate_and_sanitize_payload(raw_dict: Any) -> RawTelemetryPayload:
    """
    Sanitize and validate an incoming network telemetry payload dictionary.

    Guarantees:
    - Never crashes on invalid input (returns safe fallback payload on structural errors).
    - Safely fills missing required keys with sensible network defaults.
    - Converts stringified numeric values to standard floats.
    - Normalizes unit variations (e.g., latency in seconds to milliseconds).
    - Drops and logs warnings for malformed metrics while preserving valid metrics.

    Args:
        raw_dict: Raw dictionary (or untrusted object) representing the telemetry payload.

    Returns:
        RawTelemetryPayload: Validated and sanitized telemetry payload model.
    """
    if not isinstance(raw_dict, dict):
        logger.warning(
            "Payload ingestion rejected: expected dictionary, received %s",
            type(raw_dict).__name__,
        )
        return RawTelemetryPayload(
            scenario_id="unknown_scenario",
            target_device="unknown_device",
            metrics=[],
            metadata={"ingestion_error": f"Invalid payload type: {type(raw_dict).__name__}"},
        )

    try:
        raw_scenario = raw_dict.get("scenario_id")
        scenario_id = str(raw_scenario).strip() if raw_scenario is not None and str(raw_scenario).strip() else "unknown_scenario"

        raw_target = raw_dict.get("target_device")
        target_device = str(raw_target).strip() if raw_target is not None and str(raw_target).strip() else "unknown_device"

        raw_metadata = raw_dict.get("metadata")
        if isinstance(raw_metadata, dict):
            metadata = dict(raw_metadata)
        else:
            if raw_metadata is not None:
                logger.warning("Metadata was provided as non-dict (%r); resetting to empty dict.", type(raw_metadata).__name__)
            metadata = {}

        raw_metrics = raw_dict.get("metrics")
        if raw_metrics is None:
            raw_metrics = []
        elif not isinstance(raw_metrics, list):
            logger.warning("Payload 'metrics' field is not a list (%s); dropping metrics.", type(raw_metrics).__name__)
            raw_metrics = []

        sanitized_metrics: List[TelemetryMetric] = []

        for idx, item in enumerate(raw_metrics):
            if not isinstance(item, dict):
                logger.warning("Dropped malformed metric at index %d: item is not a dict (%r)", idx, item)
                continue

            raw_name = item.get("metric_name")
            if raw_name is None:
                raw_name = item.get("name")

            if not isinstance(raw_name, (str, int)) or not str(raw_name).strip():
                logger.warning("Dropped malformed metric at index %d: missing or invalid 'metric_name' in %r", idx, item)
                continue
            metric_name = str(raw_name).strip()

            raw_val = item.get("value")
            parsed_val = _parse_float(raw_val)
            if parsed_val is None:
                logger.warning(
                    "Dropped malformed metric at index %d ('%s'): invalid numeric value %r in %r",
                    idx,
                    metric_name,
                    raw_val,
                    item,
                )
                continue

            raw_unit = item.get("unit")
            norm_value, norm_unit = _normalize_metric_unit_and_value(metric_name, parsed_val, raw_unit)

            raw_device = item.get("device_id")
            if raw_device is not None and str(raw_device).strip():
                device_id = str(raw_device).strip()
            else:
                device_id = target_device

            raw_ts = item.get("timestamp")
            timestamp = str(raw_ts).strip() if raw_ts is not None and str(raw_ts).strip() else None

            try:
                metric_model = TelemetryMetric(
                    metric_name=metric_name,
                    value=norm_value,
                    unit=norm_unit,
                    timestamp=timestamp,
                    device_id=device_id,
                )
                sanitized_metrics.append(metric_model)
            except Exception as metric_err:
                logger.warning(
                    "Dropped metric at index %d ('%s') due to schema validation error: %s",
                    idx,
                    metric_name,
                    metric_err,
                )

        return RawTelemetryPayload(
            scenario_id=scenario_id,
            target_device=target_device,
            metrics=sanitized_metrics,
            metadata=metadata,
        )

    except Exception as unhandled_err:
        logger.error("Unexpected failure during payload validation: %s", unhandled_err, exc_info=True)
        return RawTelemetryPayload(
            scenario_id="corrupted_scenario",
            target_device="unknown_device",
            metrics=[],
            metadata={"validation_error": str(unhandled_err)},
        )
