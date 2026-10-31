"""Ingestion validation & sanitation (Member 4).

sanitize_payload() accepts ANY input (dict, JSON string, None, garbage) and
NEVER raises. It returns a ValidationResult whose status is:
  - "ok"                   : every metric was clean
  - "degraded"             : usable, but some fields were repaired or dropped
  - "insufficient_evidence": too little valid data -> reporter emits an
                             insufficient_evidence report instead of crashing
"""
from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MIN_VALID_METRICS = 2

# canonical metric -> accepted aliases (value = multiplier into canonical unit)
METRIC_SPECS: Dict[str, Dict[str, Any]] = {
    "throughput_mbps": {
        "aliases": {"throughput_mbps": 1.0, "throughput_gbps": 1000.0, "throughput_kbps": 0.001},
        "min": 0.0, "max": None,
    },
    "link_utilization_pct": {
        "aliases": {"link_utilization_pct": 1.0, "utilization_pct": 1.0, "link_utilization": 1.0},
        "min": 0.0, "max": 100.0,
    },
    "queue_drops": {
        "aliases": {"queue_drops": 1.0, "queue_drop_count": 1.0},
        "min": 0.0, "max": None,
    },
    "rtt_ms": {
        "aliases": {"rtt_ms": 1.0, "latency_ms": 1.0, "rtt_s": 1000.0, "latency_s": 1000.0, "rtt_us": 0.001},
        "min": 0.0, "max": None,
    },
    "packet_loss_pct": {
        "aliases": {"packet_loss_pct": 1.0, "loss_pct": 1.0, "packet_loss_ratio": 100.0},
        "min": 0.0, "max": 100.0,
    },
    "crc_errors": {
        "aliases": {"crc_errors": 1.0, "crc_error_count": 1.0},
        "min": 0.0, "max": None,
    },
    "interface_flaps": {
        "aliases": {"interface_flaps": 1.0, "link_flaps": 1.0, "flap_count": 1.0},
        "min": 0.0, "max": None,
    },
}

_NUM = re.compile(r"^[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")
_NULLS = {"", "null", "none", "nan", "n/a", "na", "-", "--", "undefined"}


@dataclass
class ValidationResult:
    status: str
    payload: Dict[str, Any]
    issues: List[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.status != "insufficient_evidence"

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status, "payload": self.payload, "issues": list(self.issues)}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _to_float(value: Any) -> Optional[float]:
    """Best-effort numeric coercion. Returns None for anything unusable."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        f = float(value)
    elif isinstance(value, str):
        s = value.strip().lower().replace(",", "")
        if s in _NULLS:
            return None
        m = _NUM.match(s)
        if not m:
            return None
        f = float(m.group(0))
    else:
        return None
    return f if math.isfinite(f) else None


def _parse_timestamp(value: Any) -> Optional[str]:
    try:
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, (int, float)):
            seconds = float(value) / 1000.0 if value > 1e11 else float(value)
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(timespec="seconds")
        if isinstance(value, str) and value.strip():
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat(timespec="seconds")
    except (ValueError, OverflowError, OSError):
        pass
    return None


def _insufficient(issues: List[str], device_id: str = "unknown-device") -> ValidationResult:
    return ValidationResult(
        status="insufficient_evidence",
        payload={"timestamp": _now_iso(), "device_id": device_id, "metrics": {}},
        issues=issues,
    )


def _lower_keys(d: Dict[Any, Any]) -> Dict[str, Any]:
    return {str(k).strip().lower(): v for k, v in d.items()}


def _sanitize(raw: Any, issues: List[str]) -> ValidationResult:
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            issues.append("payload is not valid JSON")
            return _insufficient(issues)
    if not isinstance(raw, dict):
        issues.append(f"payload must be an object, got {type(raw).__name__}")
        return _insufficient(issues)

    data = _lower_keys(raw)

    # --- where do the metrics live? nested "metrics"/"telemetry" or top level
    nested = data.get("metrics", data.get("telemetry"))
    top_level = {k: v for k, v in data.items() if k not in ("metrics", "telemetry")}
    if isinstance(nested, dict):
        source = {**top_level, **_lower_keys(nested)}
    else:
        if nested is not None:
            issues.append("'metrics' present but not an object; falling back to top-level fields")
        source = top_level

    # --- timestamp
    ts_raw = data.get("timestamp", data.get("time"))
    timestamp = _parse_timestamp(ts_raw)
    if timestamp is None:
        issues.append("timestamp missing; defaulted to current UTC time" if ts_raw in (None, "")
                      else f"timestamp unparseable ({ts_raw!r}); defaulted to current UTC time")
        timestamp = _now_iso()

    # --- device id
    device_id = data.get("device_id", data.get("device"))
    device_id = str(device_id).strip() if device_id not in (None, "") else "unknown-device"
    if device_id == "unknown-device":
        issues.append("device_id missing; defaulted to 'unknown-device'")

    # --- metrics
    metrics: Dict[str, float] = {}
    for canonical, spec in METRIC_SPECS.items():
        for alias, factor in spec["aliases"].items():
            if alias not in source:
                continue
            value = _to_float(source[alias])
            if value is None:
                issues.append(f"{alias}: null or non-numeric value ({source[alias]!r}); dropped")
                continue
            if isinstance(source[alias], str):
                issues.append(f"{alias}: string coerced to number")
            value *= factor
            if factor != 1.0:
                issues.append(f"{alias}: unit normalized to {canonical} (x{factor:g})")
            lo, hi = spec["min"], spec["max"]
            if (lo is not None and value < lo) or (hi is not None and value > hi):
                issues.append(f"{alias}: value {value:g} outside valid range; dropped")
                continue
            metrics[canonical] = round(value, 6)
            break

    payload = {"timestamp": timestamp, "device_id": device_id, "metrics": metrics}

    if len(metrics) < MIN_VALID_METRICS:
        issues.append(f"only {len(metrics)} valid metric(s); need at least {MIN_VALID_METRICS}")
        return ValidationResult("insufficient_evidence", payload, issues)

    status = "degraded" if issues else "ok"
    return ValidationResult(status, payload, issues)


def sanitize_payload(raw: Any) -> ValidationResult:
    """Clean and validate an incoming telemetry payload. Never raises."""
    issues: List[str] = []
    try:
        result = _sanitize(raw, issues)
    except Exception as exc:  # last line of defence: log, don't crash the pipeline
        logger.exception("validator failed unexpectedly")
        issues.append(f"unexpected validator error: {type(exc).__name__}")
        result = _insufficient(issues)
    if result.issues:
        logger.warning("input issues (%s): %s", result.status, "; ".join(result.issues))
    return result