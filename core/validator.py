"""
core/validator.py
Ingestion sanitizer and normalizer for network telemetry payloads in NetCoop AI.
"""

import logging
import math
import re
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

_UNIT_IN_VALUE_REGEX = re.compile(
    r"^([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)\s*([a-zA-Z%_/]+.*)?$"
)


def _parse_float_and_unit(val: Any) -> Tuple[Optional[float], Optional[str]]:
    """
    Safely parse raw value into a finite float and any embedded unit suffix.
    Rejects booleans, None, NaNs, infinities, and unparseable strings.
    """
    if isinstance(val, bool) or val is None:
        return None, None

    if isinstance(val, (int, float)):
        num = float(val)
        if math.isnan(num) or math.isinf(num):
            return None, None
        return num, None

    if isinstance(val, str):
        cleaned = val.strip().replace(",", "")
        if not cleaned:
            return None, None

        # Direct float parse first
        try:
            num = float(cleaned)
            if math.isnan(num) or math.isinf(num):
                return None, None
            return num, None
        except ValueError:
            pass

        # Regex match for embedded unit suffix (e.g. "142.5ms", "94%", "160 drops")
        m = _UNIT_IN_VALUE_REGEX.match(cleaned)
        if m:
            try:
                num = float(m.group(1))
                if math.isnan(num) or math.isinf(num):
                    return None, None
                extracted_unit = m.group(2).strip() if m.group(2) else None
                return num, extracted_unit
            except ValueError:
                return None, None

    return None, None


def _parse_float(val: Any) -> Optional[float]:
    """
    Safely parse raw value into a finite float.
    Rejects booleans, None, NaNs, infinities, and unparseable strings.
    """
    num, _ = _parse_float_and_unit(val)
    return num


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
    - Records comprehensive ingestion notes (dropped metrics, unit conversions,
      unknown schema versions, renamed fields, structural type adaptations) in metadata.

    Args:
        raw_dict: Raw dictionary (or untrusted object) representing the telemetry payload.

    Returns:
        RawTelemetryPayload: Validated and sanitized telemetry payload model.
    """
    if not isinstance(raw_dict, dict):
        type_name = type(raw_dict).__name__
        logger.warning(
            "Payload ingestion rejected: expected dictionary, received %s",
            type_name,
        )
        return RawTelemetryPayload(
            scenario_id="unknown_scenario",
            target_device="unknown_device",
            metrics=[],
            metadata={
                "ingestion_error": f"Invalid payload type: {type_name}",
                "ingestion_notes": [f"payload was not a dict (received '{type_name}')"],
            },
        )

    try:
        notes: List[str] = []

        raw_metadata = raw_dict.get("metadata")
        if isinstance(raw_metadata, dict):
            metadata = dict(raw_metadata)
            if "ingestion_notes" in metadata:
                existing_notes = metadata["ingestion_notes"]
                if isinstance(existing_notes, list):
                    notes.extend([str(n) for n in existing_notes])
                elif isinstance(existing_notes, str):
                    notes.append(existing_notes)
        else:
            if raw_metadata is not None:
                logger.warning("Metadata was provided as non-dict (%r); resetting to empty dict.", type(raw_metadata).__name__)
                notes.append(f"renamed or reset metadata: provided as {type(raw_metadata).__name__}, reset to empty dict")
            metadata = {}

        # Schema version check
        raw_version = raw_dict.get("schema_version")
        if raw_version is None and isinstance(raw_metadata, dict):
            raw_version = raw_metadata.get("schema_version")
        if raw_version is None:
            raw_version = raw_dict.get("version")
        if raw_version is not None:
            v_str = str(raw_version).strip()
            if v_str.lower() not in {"1.0", "v1", "1.0.0", "netcoop-v1", "v1.0"}:
                notes.append(f"unknown schema version '{v_str}' (expected v1.0)")

        # Target device resolution & alias detection
        raw_target = raw_dict.get("target_device")
        if raw_target is not None and str(raw_target).strip():
            target_device = str(raw_target).strip()
        else:
            alias_target = None
            for alias in ("device", "target", "device_id", "hostname", "node"):
                if alias in raw_dict and raw_dict[alias] is not None and str(raw_dict[alias]).strip():
                    alias_target = str(raw_dict[alias]).strip()
                    notes.append(f"renamed field: used '{alias}' for 'target_device'")
                    break
            target_device = alias_target if alias_target else "unknown_device"

        # Scenario ID resolution & alias detection
        raw_scenario = raw_dict.get("scenario_id")
        if raw_scenario is not None and str(raw_scenario).strip():
            scenario_id = str(raw_scenario).strip()
        else:
            alias_scenario = None
            for alias in ("scenario", "id", "test_id", "scenario_name"):
                if alias in raw_dict and raw_dict[alias] is not None and str(raw_dict[alias]).strip():
                    alias_scenario = str(raw_dict[alias]).strip()
                    notes.append(f"renamed field: used '{alias}' for 'scenario_id'")
                    break
            scenario_id = alias_scenario if alias_scenario else "unknown_scenario"

        # Metrics collection resolution & dict conversion
        raw_metrics = raw_dict.get("metrics")
        if raw_metrics is None:
            for alias in ("telemetry", "metric_list", "data_points"):
                if alias in raw_dict:
                    raw_metrics = raw_dict[alias]
                    notes.append(f"renamed field: used '{alias}' for 'metrics'")
                    break

        if raw_metrics is None:
            raw_metrics = []
        elif isinstance(raw_metrics, dict):
            notes.append("metrics field was a dict and was converted to a list")
            converted_list: List[Dict[str, Any]] = []
            for k, v in raw_metrics.items():
                if isinstance(v, dict):
                    item = dict(v)
                    if "metric_name" not in item and "name" not in item:
                        item["metric_name"] = str(k)
                    converted_list.append(item)
                else:
                    converted_list.append({
                        "metric_name": str(k),
                        "value": v,
                    })
            raw_metrics = converted_list
        elif not isinstance(raw_metrics, list):
            logger.warning("Payload 'metrics' field is not a list (%s); dropping metrics.", type(raw_metrics).__name__)
            notes.append(f"metrics field was neither a list nor dict (type '{type(raw_metrics).__name__}') and could not be parsed")
            raw_metrics = []

        sanitized_metrics: List[TelemetryMetric] = []

        for idx, item in enumerate(raw_metrics):
            if not isinstance(item, dict):
                logger.warning("Dropped malformed metric at index %d: item is not a dict (%r)", idx, item)
                notes.append(f"dropped metric at index {idx}: item is not a dict ({item!r})")
                continue

            raw_name = item.get("metric_name")
            if raw_name is None:
                for alias in ("name", "metric", "key", "id"):
                    if item.get(alias) is not None and str(item[alias]).strip():
                        raw_name = item[alias]
                        notes.append(f"renamed field: used '{alias}' for 'metric_name' at index {idx}")
                        break

            if not isinstance(raw_name, (str, int)) or not str(raw_name).strip():
                logger.warning("Dropped malformed metric at index %d: missing or invalid 'metric_name' in %r", idx, item)
                notes.append(f"dropped metric at index {idx}: missing or invalid 'metric_name'")
                continue
            metric_name = str(raw_name).strip()

            raw_val = item.get("value")
            if raw_val is None:
                for alias in ("val", "v", "reading"):
                    if item.get(alias) is not None:
                        raw_val = item[alias]
                        notes.append(f"renamed field: used '{alias}' for 'value' on '{metric_name}' at index {idx}")
                        break

            parsed_val, embedded_unit = _parse_float_and_unit(raw_val)
            if parsed_val is None:
                logger.warning(
                    "Dropped malformed metric at index %d ('%s'): invalid numeric value %r in %r",
                    idx,
                    metric_name,
                    raw_val,
                    item,
                )
                notes.append(f"dropped metric '{metric_name}' at index {idx}: invalid numeric value {raw_val!r}")
                continue

            raw_unit = item.get("unit")
            if (raw_unit is None or not str(raw_unit).strip()) and embedded_unit:
                raw_unit = embedded_unit
                notes.append(f"extracted unit '{embedded_unit}' from value '{raw_val}' on '{metric_name}' at index {idx}")
            elif embedded_unit and raw_unit and str(raw_unit).strip().lower() != embedded_unit.lower():
                notes.append(f"value embedded unit '{embedded_unit}' accompanied raw unit '{raw_unit}' on '{metric_name}' at index {idx}")

            norm_value, norm_unit = _normalize_metric_unit_and_value(metric_name, parsed_val, raw_unit)
            raw_unit_str = str(raw_unit).strip() if raw_unit is not None else ""
            if (norm_value != parsed_val) or (raw_unit_str.lower() != norm_unit.lower()):
                notes.append(f"unit conversion: normalized '{metric_name}' from {parsed_val} {raw_unit_str or 'dimensionless'} to {norm_value} {norm_unit}")

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
                notes.append(f"dropped metric '{metric_name}' at index {idx} due to schema validation error: {metric_err}")

        if notes or "ingestion_notes" in metadata:
            metadata["ingestion_notes"] = notes

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
            metadata={
                "validation_error": str(unhandled_err),
                "ingestion_notes": [f"Unexpected ingestion failure: {unhandled_err}"],
            },
        )
