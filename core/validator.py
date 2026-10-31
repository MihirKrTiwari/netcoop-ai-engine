"""
core/validator.py
Ingestion validation, normalization, and sanitation for network telemetry payloads in NetCoop AI.

Provides:
1. CANONICAL_METRIC_MAP & CANONICAL_UNITS_MAP: Single source of truth for canonical metric names and units.
2. validate_and_sanitize_payload(): Diagnostic pipeline ingestion returning RawTelemetryPayload.
3. sanitize_payload(): Section 4 validation returning ValidationResult (Member 4 specification).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from core.schemas import RawTelemetryPayload, TelemetryMetric

logger = logging.getLogger(__name__)

# ==============================================================================
# Single Source of Truth: Canonical Metric Mappings, Units & Thresholds
# ==============================================================================

CANONICAL_METRIC_MAP: Dict[str, str] = {
    # Latency / Round-Trip Time
    "rtt_ms": "rtt_latency_ms",
    "latency_ms": "rtt_latency_ms",
    "rtt": "rtt_latency_ms",
    "latency": "rtt_latency_ms",
    "rtt_latency": "rtt_latency_ms",
    "rtt_latency_ms": "rtt_latency_ms",
    "rtt_s": "rtt_latency_ms",
    "latency_s": "rtt_latency_ms",
    "rtt_us": "rtt_latency_ms",
    "rtt_usec": "rtt_latency_ms",
    "round_trip_time_ms": "rtt_latency_ms",
    "rtt_time_ms": "rtt_latency_ms",

    # Packet Loss
    "packet_loss_pct": "packet_loss_pct",
    "packet_loss": "packet_loss_pct",
    "loss_pct": "packet_loss_pct",
    "loss": "packet_loss_pct",
    "packet_loss_percent": "packet_loss_pct",
    "packet_loss_ratio": "packet_loss_pct",
    "loss_percentage": "packet_loss_pct",

    # Jitter
    "jitter": "jitter_ms",
    "jitter_ms": "jitter_ms",
    "packet_jitter_ms": "jitter_ms",
    "delay_variation_ms": "jitter_ms",

    # Link Utilization
    "link_utilization_pct": "link_utilization_pct",
    "link_utilization": "link_utilization_pct",
    "utilization_pct": "link_utilization_pct",
    "utilization": "link_utilization_pct",
    "bandwidth_utilization": "link_utilization_pct",
    "interface_utilization": "link_utilization_pct",
    "if_utilization_pct": "link_utilization_pct",

    # Throughput / Bandwidth
    "throughput_mbps": "throughput_mbps",
    "throughput": "throughput_mbps",
    "throughput_gbps": "throughput_mbps",
    "throughput_kbps": "throughput_mbps",
    "bandwidth_mbps": "throughput_mbps",
    "bandwidth": "throughput_mbps",
    "rx_bandwidth_mbps": "throughput_mbps",
    "tx_bandwidth_mbps": "throughput_mbps",
    "rx_throughput_mbps": "throughput_mbps",
    "tx_throughput_mbps": "throughput_mbps",
    "bandwidth_bps": "throughput_mbps",
    "throughput_bps": "throughput_mbps",
    "data_rate_mbps": "throughput_mbps",
    "egress_throughput": "throughput_mbps",
    "ingress_throughput": "throughput_mbps",

    # CPU Utilization
    "cpu_utilization_pct": "cpu_utilization_pct",
    "cpu_utilization": "cpu_utilization_pct",
    "cpu": "cpu_utilization_pct",
    "cpu_pct": "cpu_utilization_pct",
    "processor_utilization": "cpu_utilization_pct",

    # Memory / RAM Utilization
    "memory_utilization_pct": "memory_utilization_pct",
    "memory_utilization": "memory_utilization_pct",
    "memory": "memory_utilization_pct",
    "ram_pct": "memory_utilization_pct",
    "memory_pct": "memory_utilization_pct",
    "ram": "memory_utilization_pct",

    # Egress Queue Drops
    "egress_queue_drops": "egress_queue_drops",
    "queue_drops": "egress_queue_drops",
    "egress_drops": "egress_queue_drops",
    "tx_drops": "egress_queue_drops",
    "queue_drop_count": "egress_queue_drops",
    "tail_drops": "egress_queue_drops",

    # Physical Layer CRC / FCS Errors
    "interface_crc_errors": "interface_crc_errors",
    "crc_errors": "interface_crc_errors",
    "fcs_errors": "interface_crc_errors",
    "rx_crc_errors": "interface_crc_errors",
    "crc_error_count": "interface_crc_errors",
    "fcs_error_count": "interface_crc_errors",

    # Interface Packet Errors
    "interface_errors": "interface_errors",
    "if_errors": "interface_errors",
    "port_errors": "interface_errors",
    "rx_errors": "interface_errors",
    "tx_errors": "interface_errors",
    "packet_errors": "interface_errors",

    # Link Flaps
    "link_flaps": "link_flaps",
    "carrier_transitions": "link_flaps",
    "flaps": "link_flaps",
    "interface_flaps": "link_flaps",
    "port_flaps": "link_flaps",
    "flap_count": "link_flaps",

    # Operational Link Status
    "oper_status": "oper_status",
    "link_state": "oper_status",
    "if_oper_status": "oper_status",
    "port_status": "oper_status",
    "interface_state": "oper_status",

    # Node / Device Status
    "device_status": "device_status",
    "node_status": "device_status",
    "system_health": "device_status",
    "device_state": "device_status",
    "chassis_status": "device_status",

    # Wireless 802.11 Metrics
    "rssi_dbm": "rssi_dbm",
    "rssi": "rssi_dbm",
    "signal_strength_dbm": "rssi_dbm",
    "rx_power_dbm": "rssi_dbm",
    "wifi_rssi_dbm": "rssi_dbm",
    "wireless_rssi": "rssi_dbm",
    "signal_dbm": "rssi_dbm",

    "snr_db": "snr_db",
    "snr": "snr_db",
    "signal_to_noise_ratio": "snr_db",
    "snr_ratio_db": "snr_db",
    "wifi_snr_db": "snr_db",
    "wireless_snr": "snr_db",

    "retransmission_rate_pct": "retransmission_rate_pct",
    "retransmission_rate": "retransmission_rate_pct",
    "retransmissions_pct": "retransmission_rate_pct",
    "retransmission_pct": "retransmission_rate_pct",
    "retry_rate_pct": "retransmission_rate_pct",
    "retry_rate": "retransmission_rate_pct",
    "wifi_retry_rate_pct": "retransmission_rate_pct",
    "packet_retry_pct": "retransmission_rate_pct",

    # Core Services (DNS / DHCP)
    "dns_resolution_time_ms": "dns_resolution_time_ms",
    "dns_resolution_time": "dns_resolution_time_ms",
    "dns_latency_ms": "dns_resolution_time_ms",
    "dns_response_time_ms": "dns_resolution_time_ms",
    "dns_lookup_time_ms": "dns_resolution_time_ms",
    "dns_time_ms": "dns_resolution_time_ms",
    "dns_rtt_ms": "dns_resolution_time_ms",
    "dns_time": "dns_resolution_time_ms",

    "dns_failure_rate_pct": "dns_failure_rate_pct",
    "dns_failure_rate": "dns_failure_rate_pct",
    "dns_error_rate_pct": "dns_failure_rate_pct",
    "dns_failure_pct": "dns_failure_rate_pct",
    "dns_failures_pct": "dns_failure_rate_pct",
    "dns_timeout_rate_pct": "dns_failure_rate_pct",

    "dhcp_discover_failures": "dhcp_discover_failures",
    "dhcp_failures": "dhcp_discover_failures",
    "dhcp_timeouts": "dhcp_discover_failures",
    "dhcp_discover_drops": "dhcp_discover_failures",
    "dhcp_nak_count": "dhcp_discover_failures",
    "dhcp_lease_failures": "dhcp_discover_failures",
}

CANONICAL_UNITS_MAP: Dict[str, str] = {
    "rtt_latency_ms": "ms",
    "packet_loss_pct": "%",
    "jitter_ms": "ms",
    "link_utilization_pct": "%",
    "throughput_mbps": "Mbps",
    "cpu_utilization_pct": "%",
    "memory_utilization_pct": "%",
    "egress_queue_drops": "count",
    "interface_crc_errors": "count",
    "interface_errors": "count",
    "link_flaps": "count",
    "oper_status": "state",
    "device_status": "state",
    "rssi_dbm": "dBm",
    "snr_db": "dB",
    "retransmission_rate_pct": "%",
    "dns_resolution_time_ms": "ms",
    "dns_failure_rate_pct": "%",
    "dhcp_discover_failures": "count",
}

CANONICAL_THRESHOLDS_MAP: Dict[str, Dict[str, Any]] = {
    "rtt_latency_ms": {"warning": 80.0, "critical": 150.0, "unit": "ms", "owner": "TelemetryAgent"},
    "packet_loss_pct": {"warning": 2.0, "critical": 5.0, "unit": "%", "owner": "TelemetryAgent"},
    "jitter_ms": {"warning": 25.0, "critical": 50.0, "unit": "ms", "owner": "TelemetryAgent"},
    "link_utilization_pct": {"warning": 80.0, "critical": 90.0, "unit": "%", "owner": "TelemetryAgent"},
    "throughput_mbps": {"min": 1.0, "unit": "Mbps", "owner": "TelemetryAgent"},
    "cpu_utilization_pct": {"warning": 85.0, "critical": 95.0, "unit": "%", "owner": "InfrastructureAgent"},
    "memory_utilization_pct": {"warning": 90.0, "critical": 95.0, "unit": "%", "owner": "InfrastructureAgent"},
    "egress_queue_drops": {"threshold": 0.0, "unit": "count", "owner": "InfrastructureAgent"},
    "interface_crc_errors": {"threshold": 5.0, "unit": "count", "owner": "InfrastructureAgent"},
    "interface_errors": {"threshold": 10.0, "unit": "count", "owner": "InfrastructureAgent"},
    "link_flaps": {"threshold": 3.0, "unit": "count", "owner": "InfrastructureAgent"},
    "oper_status": {"down": 0.0, "up": 1.0, "unit": "state", "owner": "InfrastructureAgent"},
    "device_status": {"down": 0.0, "up": 1.0, "unit": "state", "owner": "InfrastructureAgent"},
    "rssi_dbm": {"threshold": -75.0, "unit": "dBm", "owner": "WirelessAgent"},
    "snr_db": {"threshold": 15.0, "unit": "dB", "owner": "WirelessAgent"},
    "retransmission_rate_pct": {"threshold": 10.0, "unit": "%", "owner": "WirelessAgent"},
    "dns_resolution_time_ms": {"threshold": 500.0, "unit": "ms", "owner": "ServiceAgent"},
    "dns_failure_rate_pct": {"threshold": 5.0, "unit": "%", "owner": "ServiceAgent"},
    "dhcp_discover_failures": {"threshold": 3.0, "unit": "count", "owner": "ServiceAgent"},
}


# ==============================================================================
# Helper Parsing Functions
# ==============================================================================

_SECONDS_UNITS = frozenset({"s", "sec", "secs", "second", "seconds"})
_MILLISECONDS_UNITS = frozenset({"ms", "msec", "msecs", "millisecond", "milliseconds"})
_MICROSECONDS_UNITS = frozenset({"us", "µs", "usec", "microsecond", "microseconds"})
_NANOSECONDS_UNITS = frozenset({"ns", "nsec", "nanosecond", "nanoseconds"})
_PERCENT_UNITS = frozenset({"%", "pct", "percent", "percentage"})
_RATIO_UNITS = frozenset({"ratio", "fraction"})

_UNIT_IN_VALUE_REGEX = re.compile(
    r"^([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)\s*([a-zA-Z%_/]+.*)?$"
)
_NUM = re.compile(r"^[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")
_NULLS = {"", "null", "none", "nan", "n/a", "na", "-", "--", "undefined", "???"}


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
        if not cleaned or cleaned.lower() in _NULLS:
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


def _to_float(value: Any) -> Optional[float]:
    """Best-effort numeric coercion for simple values."""
    num, _ = _parse_float_and_unit(value)
    return num


def _normalize_metric_unit_and_value(
    canonical_name: str,
    value: float,
    raw_unit: Any,
) -> Tuple[float, str]:
    """
    Normalize metric unit variations and convert units to canonical network standards.
    Specifically converts latency in seconds/microseconds to milliseconds and ratios to percentages.
    If no unit is provided, falls back to the canonical unit for that metric.
    """
    unit_str = str(raw_unit).strip() if raw_unit is not None else ""
    norm_unit = unit_str.lower()

    # Time normalization -> ms
    if norm_unit in _SECONDS_UNITS:
        return (value * 1000.0, "ms")
    elif norm_unit in _MICROSECONDS_UNITS:
        return (value / 1000.0, "ms")
    elif norm_unit in _NANOSECONDS_UNITS:
        return (value / 1_000_000.0, "ms")
    elif norm_unit in _MILLISECONDS_UNITS:
        return (value, "ms")

    # Percentage / Ratio normalization -> %
    elif norm_unit in _RATIO_UNITS:
        return (value * 100.0, "%")
    elif norm_unit in _PERCENT_UNITS:
        return (value, "%")

    # Rate normalization casing
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

    # Unitless fallback: assign canonical unit if available
    if not norm_unit or norm_unit in {"dimensionless", "none", "count"}:
        canonical_unit = CANONICAL_UNITS_MAP.get(canonical_name)
        if canonical_unit:
            return (value, canonical_unit)

    fallback_unit = unit_str if unit_str else "dimensionless"
    return (value, fallback_unit)


# ==============================================================================
# Pipeline Ingestion: validate_and_sanitize_payload
# ==============================================================================

def validate_and_sanitize_payload(raw_dict: Any) -> RawTelemetryPayload:
    """
    Sanitize and validate an incoming network telemetry payload dictionary.

    Guarantees:
    - Never crashes on invalid input (returns safe fallback payload on structural errors).
    - Canonicalizes incoming metric aliases to single-source-of-truth canonical names.
    - Converts stringified numeric values and extracts embedded unit suffixes.
    - Normalizes units (seconds -> ms, ratio -> %) and assigns canonical units.
    - Emits clean limitation notes only when a material rename or conversion occurs.
    - Handles missing/malformed payloads gracefully.
    """
    if isinstance(raw_dict, str):
        cleaned_str = raw_dict.lstrip("\ufeff").strip()
        if not cleaned_str:
            return RawTelemetryPayload(
                scenario_id="unknown_scenario",
                target_device="unknown_device",
                metrics=[],
                metadata={
                    "ingestion_error": "Input string is empty",
                    "ingestion_notes": ["input JSON string is empty"],
                },
            )
        try:
            raw_dict = json.loads(cleaned_str)
        except Exception as exc:
            return RawTelemetryPayload(
                scenario_id="unknown_scenario",
                target_device="unknown_device",
                metrics=[],
                metadata={
                    "ingestion_error": f"Malformed JSON string: {exc}",
                    "ingestion_notes": [f"malformed JSON string: {exc}"],
                },
            )

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

        # 1. Metadata resolution
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

        # 2. Schema version check
        raw_version = raw_dict.get("schema_version")
        if raw_version is None and isinstance(raw_metadata, dict):
            raw_version = raw_metadata.get("schema_version")
        if raw_version is None:
            raw_version = raw_dict.get("version")
        if raw_version is not None:
            v_str = str(raw_version).strip()
            metadata["schema_version"] = v_str
            if v_str.lower() not in {"1.0", "v1", "1.0.0", "netcoop-v1", "v1.0"}:
                notes.append(f"unknown schema version '{v_str}' (unsupported schema_version, expected v1.0)")

        # 3. Target device resolution
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

        # 4. Scenario ID resolution
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

        # 5. Metrics collection resolution
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

        # Global timestamp fallback from root payload if present
        root_timestamp = raw_dict.get("timestamp")
        root_ts_str = str(root_timestamp).strip() if root_timestamp is not None and str(root_timestamp).strip() else None

        sanitized_metrics: List[TelemetryMetric] = []
        raw_valid_metric_count = 0
        raw_dropped_count = 0

        for idx, item in enumerate(raw_metrics):
            if not isinstance(item, dict):
                logger.warning("Dropped malformed metric at index %d: item is not a dict (%r)", idx, item)
                notes.append(f"dropped metric at index {idx}: item is not a dict ({item!r})")
                raw_dropped_count += 1
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
                raw_dropped_count += 1
                continue
            orig_name = str(raw_name).strip()
            orig_name_clean = orig_name.lower().strip()

            raw_val = item.get("value")
            if raw_val is None:
                for alias in ("val", "v", "reading"):
                    if item.get(alias) is not None:
                        raw_val = item[alias]
                        notes.append(f"renamed field: used '{alias}' for 'value' on '{orig_name}' at index {idx}")
                        break

            parsed_val, embedded_unit = _parse_float_and_unit(raw_val)
            if parsed_val is None:
                logger.warning(
                    "Dropped malformed metric at index %d ('%s'): invalid numeric value %r in %r",
                    idx,
                    orig_name,
                    raw_val,
                    item,
                )
                notes.append(f"dropped metric '{orig_name}' at index {idx}: invalid numeric value {raw_val!r}")
                raw_dropped_count += 1
                continue

            # Alias-specific pre-conversions (e.g. rtt_s in seconds)
            if orig_name_clean in {"rtt_s", "latency_s"}:
                parsed_val = parsed_val * 1000.0
                if not embedded_unit:
                    embedded_unit = "ms"
            elif orig_name_clean in {"rtt_us", "rtt_usec"}:
                parsed_val = parsed_val / 1000.0
                if not embedded_unit:
                    embedded_unit = "ms"
            elif orig_name_clean in {"throughput_gbps"}:
                parsed_val = parsed_val * 1000.0
                if not embedded_unit:
                    embedded_unit = "Mbps"
            elif orig_name_clean in {"throughput_kbps"}:
                parsed_val = parsed_val / 1000.0
                if not embedded_unit:
                    embedded_unit = "Mbps"
            elif orig_name_clean in {"packet_loss_ratio"}:
                parsed_val = parsed_val * 100.0
                if not embedded_unit:
                    embedded_unit = "%"

            # Canonicalize metric name
            canonical_name = CANONICAL_METRIC_MAP.get(orig_name_clean, orig_name)
            if orig_name != canonical_name:
                notes.append(f"canonicalized metric alias '{orig_name}' to '{canonical_name}'")

            raw_unit = item.get("unit")
            if (raw_unit is None or not str(raw_unit).strip()) and embedded_unit:
                raw_unit = embedded_unit
                notes.append(f"extracted unit '{embedded_unit}' from value '{raw_val}' on '{canonical_name}' at index {idx}")
            elif embedded_unit and raw_unit and str(raw_unit).strip().lower() != embedded_unit.lower():
                notes.append(f"value embedded unit '{embedded_unit}' accompanied raw unit '{raw_unit}' on '{canonical_name}' at index {idx}")

            norm_value, norm_unit = _normalize_metric_unit_and_value(canonical_name, parsed_val, raw_unit)
            raw_unit_str = str(raw_unit).strip() if raw_unit is not None else ""
            if (norm_value != parsed_val) or (raw_unit_str and raw_unit_str.lower() != norm_unit.lower() and norm_unit != "dimensionless"):
                notes.append(f"unit conversion: normalized '{canonical_name}' from {parsed_val} {raw_unit_str or 'dimensionless'} to {norm_value} {norm_unit}")

            raw_device = item.get("device_id")
            if raw_device is not None and str(raw_device).strip():
                device_id = str(raw_device).strip()
            else:
                device_id = target_device

            raw_ts = item.get("timestamp")
            if raw_ts is not None and str(raw_ts).strip():
                timestamp = str(raw_ts).strip()
            else:
                timestamp = root_ts_str

            try:
                metric_model = TelemetryMetric(
                    metric_name=canonical_name,
                    value=norm_value,
                    unit=norm_unit,
                    timestamp=timestamp,
                    device_id=device_id,
                )
                sanitized_metrics.append(metric_model)
                raw_valid_metric_count += 1
            except Exception as metric_err:
                logger.warning(
                    "Dropped metric at index %d ('%s') due to schema validation error: %s",
                    idx,
                    canonical_name,
                    metric_err,
                )
                notes.append(f"dropped metric '{canonical_name}' at index {idx} due to schema validation error: {metric_err}")
                raw_dropped_count += 1

        # Check for mostly-unusable corrupt input (m4_E pattern)
        if len(raw_metrics) > 0 and raw_dropped_count > 0:
            if len(sanitized_metrics) == 0:
                metadata["mostly_unusable"] = True
                metadata["unusable_reason"] = "All incoming metrics were malformed, corrupt, or unparseable."
                notes.append("Irrecoverably corrupt input: no valid numeric metrics survived validation.")
            elif len(sanitized_metrics) == 1 and raw_dropped_count >= 2:
                single = sanitized_metrics[0]
                # If the only surviving metric is below actionable threshold (e.g. CRC <= 5)
                if single.metric_name == "interface_crc_errors" and single.value <= 5.0:
                    metadata["mostly_unusable"] = True
                    metadata["unusable_reason"] = (
                        f"Mostly unusable telemetry: only 1 non-actionable metric ({single.metric_name}={single.value}) survived; "
                        f"{raw_dropped_count} metrics were corrupt or dropped."
                    )
                    notes.append(metadata["unusable_reason"])

        if notes:
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


# ==============================================================================
# Member 4 Validation Specification: sanitize_payload
# ==============================================================================

MIN_VALID_METRICS = 2

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


def _clean_metric(
    canonical: str,
    spec: Dict[str, Any],
    raw_metrics: Dict[str, Any],
    issues: List[str],
) -> Optional[float]:
    found_key, raw_val, mult = None, None, 1.0
    for alias, factor in spec["aliases"].items():
        if alias in raw_metrics:
            found_key, raw_val, mult = alias, raw_metrics[alias], factor
            break
    if found_key is None:
        return None

    val = _to_float(raw_val)
    if val is None:
        issues.append(f"dropped metric {found_key}={raw_val!r} (not a valid finite number)")
        return None

    if isinstance(raw_val, str):
        issues.append(f"coerced {found_key}={raw_val!r} to numeric {val}")

    if mult != 1.0:
        val = val * mult
        issues.append(f"normalized {found_key} -> {canonical} (*{mult})")

    min_v, max_v = spec["min"], spec["max"]
    if (min_v is not None and val < min_v) or (max_v is not None and val > max_v):
        issues.append(f"dropped metric {canonical}={val} (out of range [{min_v}, {max_v}])")
        return None

    return round(val, 4)


def _insufficient(issues: List[str]) -> ValidationResult:
    return ValidationResult(
        status="insufficient_evidence",
        payload={"timestamp": _now_iso(), "device_id": "unknown-device", "metrics": {}},
        issues=issues,
    )


def sanitize_payload(raw: Any) -> ValidationResult:
    """Safe ingestion entry point for Section 4 specification."""
    issues: List[str] = []
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            issues.append("failed to decode byte payload as UTF-8")
            return _insufficient(issues)

    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            issues.append("empty payload string")
            return _insufficient(issues)
        try:
            raw = json.loads(s)
        except json.JSONDecodeError as err:
            issues.append(f"invalid JSON: {err.msg}")
            return _insufficient(issues)

    if not isinstance(raw, dict):
        issues.append(f"payload must be a JSON object, got {type(raw).__name__}")
        return _insufficient(issues)

    raw_metrics = raw.get("metrics")
    if not isinstance(raw_metrics, dict):
        issues.append("missing or non-dict 'metrics' object")
        return _insufficient(issues)

    ts = raw.get("timestamp")
    if not ts or not isinstance(ts, str):
        ts = _now_iso()
        issues.append("missing or invalid timestamp; filled with current UTC time")

    device = raw.get("device_id") or raw.get("device")
    if not device or not isinstance(device, str):
        device = "unknown-device"
        issues.append("missing or invalid device_id; set to 'unknown-device'")

    cleaned_metrics: Dict[str, float] = {}
    for canonical, spec in METRIC_SPECS.items():
        v = _clean_metric(canonical, spec, raw_metrics, issues)
        if v is not None:
            cleaned_metrics[canonical] = v

    if len(cleaned_metrics) < MIN_VALID_METRICS:
        issues.append(
            f"only {len(cleaned_metrics)} valid metric(s); minimum is {MIN_VALID_METRICS}"
        )
        return ValidationResult(
            status="insufficient_evidence",
            payload={"timestamp": ts, "device_id": device, "metrics": cleaned_metrics},
            issues=issues,
        )

    status = "degraded" if issues else "ok"
    return ValidationResult(
        status=status,
        payload={"timestamp": ts, "device_id": device, "metrics": cleaned_metrics},
        issues=issues,
    )
