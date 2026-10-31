"""NetCoop AI - Member 2: Telemetry & Performance Agent.

This module provides both:
1. TelemetryPerformanceAgent: Standalone performance agent evaluating structured
   telemetry dictionaries against warning/high thresholds.
2. TelemetryAgent: NetCoop AI domain agent inheriting from BaseAgent that evaluates
   RawTelemetryPayload instances within the multi-agent diagnostic pipeline.

Python: 3.10+
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping, Sequence
from datetime import datetime
import math
from statistics import pstdev
from typing import Any, Dict, List, Optional

from agents.base import BaseAgent
from core.schemas import AgentFinding, MetricEvidence, RawTelemetryPayload, TelemetryMetric
from core.timeutils import is_newer

_is_newer = is_newer


# ==============================================================================
# Standalone Performance Agent Specification (Member 2)
# ==============================================================================

@dataclass(frozen=True)
class Thresholds:
    """Configurable starting thresholds for a synthetic/demo environment.

    Calibrate these values using the real service baseline before operational use.
    """

    latency_warning_ms: float = 100.0
    latency_high_ms: float = 150.0
    packet_loss_warning_pct: float = 1.0
    packet_loss_high_pct: float = 2.0
    jitter_warning_ms: float = 20.0
    jitter_high_ms: float = 30.0
    utilization_warning_pct: float = 80.0
    utilization_high_pct: float = 85.0
    rtt_variability_high_ms: float = 30.0


class TelemetryPerformanceAgent:
    """Normalize telemetry, flag performance symptoms, and emit a JSON finding."""

    agent_id = "telemetry_performance_agent"
    schema_version = "1.0"

    # The first key found is used. The structured {value, unit} form is preferred.
    aliases = {
        "rtt_latency": ("rtt_latency", "latency", "rtt"),
        "packet_loss": ("packet_loss", "packet_loss_pct", "loss"),
        "jitter": ("jitter", "jitter_ms"),
        "link_utilization": ("link_utilization", "link_utilization_pct", "utilization"),
        "throughput": ("throughput", "throughput_mbps"),
        "bandwidth": ("bandwidth", "bandwidth_mbps"),
        "rtt_samples": ("rtt_samples", "latency_samples"),
    }

    required_core_metrics = (
        "rtt_latency_ms",
        "packet_loss_pct",
        "jitter_ms",
        "link_utilization_pct",
    )

    def __init__(self, thresholds: Thresholds | None = None) -> None:
        self.thresholds = thresholds or Thresholds()

    def analyze(self, telemetry: Mapping[str, Any]) -> dict[str, Any]:
        """Analyze one device/incident telemetry record and return a JSON-safe dict."""
        if not isinstance(telemetry, Mapping):
            telemetry = {}
            envelope_error = "Input telemetry must be a JSON object."
        else:
            envelope_error = None

        incident_id = str(telemetry.get("incident_id", "UNKNOWN_INCIDENT"))
        device_id = str(telemetry.get("device_id", "UNKNOWN_DEVICE"))
        timestamp = telemetry.get("timestamp")
        limitations: list[str] = []
        if envelope_error:
            limitations.append(envelope_error)

        raw_metrics = telemetry.get("metrics", {})
        if not isinstance(raw_metrics, Mapping):
            raw_metrics = {}
            limitations.append("The metrics field is missing or is not a JSON object.")

        normalized: dict[str, float | list[float]] = {}
        source_keys: dict[str, str] = {}

        # Normalize the four core metrics plus optional throughput/bandwidth.
        normalizers = {
            "rtt_latency": ("rtt_latency_ms", self._normalize_time),
            "packet_loss": ("packet_loss_pct", self._normalize_percentage),
            "jitter": ("jitter_ms", self._normalize_time),
            "link_utilization": ("link_utilization_pct", self._normalize_percentage),
            "throughput": ("throughput_mbps", self._normalize_rate),
            "bandwidth": ("bandwidth_mbps", self._normalize_rate),
            "rtt_samples": ("rtt_samples_ms", self._normalize_time_series),
        }

        for logical_name, (output_name, normalizer) in normalizers.items():
            found_key = next((key for key in self.aliases[logical_name] if key in raw_metrics), None)
            if found_key is None:
                continue

            source_keys[output_name] = found_key
            try:
                normalized_value = normalizer(raw_metrics[found_key])
                normalized[output_name] = normalized_value
            except (TypeError, ValueError) as exc:
                limitations.append(f"Invalid {output_name} from '{found_key}': {exc}")

        # If utilization was not supplied, derive it only when both rates exist.
        if "link_utilization_pct" not in normalized:
            throughput = normalized.get("throughput_mbps")
            bandwidth = normalized.get("bandwidth_mbps")
            if isinstance(throughput, (int, float)) and isinstance(bandwidth, (int, float)) and bandwidth > 0:
                derived = (throughput / bandwidth) * 100.0
                if 0.0 <= derived <= 100.0:
                    normalized["link_utilization_pct"] = round(derived, 4)
                    source_keys["link_utilization_pct"] = "derived_from_throughput_and_bandwidth"
                    # A missing direct utilization reading is still worth documenting.
                    limitations.append("Link utilization was derived from throughput/bandwidth, not directly measured.")
                else:
                    limitations.append("Derived link utilization is outside the valid 0–100% range.")

        # Record core metrics that are still missing or unusable after normalization.
        for required_key in self.required_core_metrics:
            if required_key not in normalized:
                limitations.append(f"Missing or unusable required performance metric: {required_key}.")

        # Build metric evidence (severity + interpretation) from available values.
        evidence = self._build_evidence(normalized)
        severity_by_metric = {item["metric"]: item["severity"] for item in evidence}

        # Optional RTT series lets us test whether delay itself is variable.
        rtt_stddev = None
        samples = normalized.get("rtt_samples_ms")
        if isinstance(samples, list) and len(samples) >= 2:
            rtt_stddev = round(pstdev(samples), 4)
            normalized["rtt_stddev_ms"] = rtt_stddev

        hypotheses: list[dict[str, Any]] = []
        latency = normalized.get("rtt_latency_ms")
        loss = normalized.get("packet_loss_pct")
        jitter = normalized.get("jitter_ms")
        utilization = normalized.get("link_utilization_pct")

        latency_high = severity_by_metric.get("rtt_latency_ms") == "high"
        loss_high = severity_by_metric.get("packet_loss_pct") == "high"
        jitter_high = severity_by_metric.get("jitter_ms") == "high"
        utilization_high = severity_by_metric.get("link_utilization_pct") == "high"

        # Pattern 1: high latency + high utilization -> possible congestion.
        if latency_high and utilization_high:
            supporting = ["rtt_latency_ms", "link_utilization_pct"]
            if loss_high:
                supporting.append("packet_loss_pct")
            hypotheses.append({
                "condition": "possible_network_congestion_or_bandwidth_saturation",
                "confidence": 0.86 if loss_high else 0.82,
                "supporting_metrics": supporting,
                "explanation": "High RTT latency occurs together with high link utilization.",
            })

        # Pattern 2: high loss + latency not high + utilization not high.
        latency_not_high = isinstance(latency, (int, float)) and latency < self.thresholds.latency_high_ms
        utilization_not_high = isinstance(utilization, (int, float)) and utilization < self.thresholds.utilization_high_pct
        if loss_high and latency_not_high and utilization_not_high:
            hypotheses.append({
                "condition": "possible_path_loss_or_interface_discards",
                "confidence": 0.74,
                "supporting_metrics": ["packet_loss_pct", "rtt_latency_ms", "link_utilization_pct"],
                "explanation": "Packet loss is high while latency and link utilization are not high.",
            })

        # Pattern 3: high jitter + variable RTT samples.
        if jitter_high and rtt_stddev is not None and rtt_stddev >= self.thresholds.rtt_variability_high_ms:
            hypotheses.append({
                "condition": "possible_wireless_instability_or_queue_delay_variation",
                "confidence": 0.78,
                "supporting_metrics": ["jitter_ms", "rtt_stddev_ms"],
                "explanation": "High jitter is accompanied by substantial variation across RTT samples.",
            })
        elif jitter_high and rtt_stddev is None:
            limitations.append(
                "Jitter is high, but RTT samples were not supplied; the agent cannot verify latency variability."
            )

        # Build overall state. Do not call a partial, all-normal record fully healthy.
        present_core = [key for key in self.required_core_metrics if key in normalized]
        missing_core_count = len(self.required_core_metrics) - len(present_core)
        high_metrics = [key for key, severity in severity_by_metric.items() if severity == "high"]
        warning_metrics = [key for key, severity in severity_by_metric.items() if severity == "warning"]

        if hypotheses:
            health_state = "degraded"
            primary = hypotheses[0]
            confidence = float(primary["confidence"])
            # Reduce confidence when important evidence is unavailable.
            confidence = max(0.30, confidence - (0.04 * missing_core_count))
            summary = f"Transmission-performance symptoms support: {primary['condition']}."
        elif high_metrics or warning_metrics:
            health_state = "degraded"
            primary = {
                "condition": "performance_anomaly_detected_cause_not_isolated",
                "confidence": 0.62 if len(high_metrics) + len(warning_metrics) == 1 else 0.68,
                "supporting_metrics": high_metrics + warning_metrics,
                "explanation": "One or more performance measurements exceed the configured normal range, but no specific pattern matched.",
            }
            hypotheses.append(primary)
            confidence = max(0.30, float(primary["confidence"]) - (0.04 * missing_core_count))
            summary = "Performance anomaly detected; more evidence is needed to isolate the likely cause."
        elif missing_core_count == 0:
            health_state = "healthy"
            primary = None
            confidence = 0.90
            summary = "All four core transmission-performance metrics are within configured normal ranges."
        else:
            health_state = "unknown"
            primary = None
            confidence = 0.30
            summary = "Insufficient telemetry to classify transmission performance as healthy or degraded."

        # State the scope boundary so downstream agents do not overinterpret this finding.
        limitations.append(
            "This agent analyzes transmission symptoms only; it does not confirm internal hardware or device faults."
        )

        return {
            "schema_version": self.schema_version,
            "message_type": "agent_finding",
            "agent_id": self.agent_id,
            "incident_id": incident_id,
            "device_id": device_id,
            "timestamp": timestamp,
            "analysis_status": "complete" if missing_core_count == 0 else "partial",
            "health_state": health_state,
            "primary_hypothesis": primary["condition"] if primary else None,
            "suspected_conditions": hypotheses,
            "confidence": round(confidence, 2),
            "normalized_metrics": normalized,
            "evidence": evidence,
            "limitations": self._deduplicate(limitations),
            "summary": summary,
            "metric_sources": source_keys,
        }

    def _build_evidence(self, metrics: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Return machine-readable evidence for each normalized scalar metric."""
        specs = [
            ("rtt_latency_ms", "ms", self.thresholds.latency_warning_ms, self.thresholds.latency_high_ms,
             "Elevated round-trip latency."),
            ("packet_loss_pct", "%", self.thresholds.packet_loss_warning_pct, self.thresholds.packet_loss_high_pct,
             "Elevated packet loss."),
            ("jitter_ms", "ms", self.thresholds.jitter_warning_ms, self.thresholds.jitter_high_ms,
             "Elevated packet-delay variation."),
            ("link_utilization_pct", "%", self.thresholds.utilization_warning_pct, self.thresholds.utilization_high_pct,
             "High proportion of link capacity in use."),
        ]
        result: list[dict[str, Any]] = []
        for key, unit, warning, high, description in specs:
            value = metrics.get(key)
            if not isinstance(value, (int, float)):
                continue
            severity = "high" if value >= high else "warning" if value >= warning else "normal"
            result.append({
                "metric": key,
                "value": round(float(value), 4),
                "unit": unit,
                "severity": severity,
                "thresholds": {"warning": warning, "high": high},
                "interpretation": description if severity != "normal" else "Within the configured normal range.",
            })
        return result

    @staticmethod
    def _measurement_parts(raw: Any) -> tuple[Any, str]:
        if not isinstance(raw, Mapping):
            raise ValueError("measurement must contain 'value' and 'unit'.")
        if "value" not in raw or "unit" not in raw:
            raise ValueError("measurement must contain both 'value' and 'unit'.")
        return raw["value"], str(raw["unit"]).strip().lower()

    @staticmethod
    def _finite_number(value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("value must be numeric.")
        try:
            number = float(value)
        except OverflowError as exc:
            raise ValueError("value must be finite.") from exc
        if not math.isfinite(number):
            raise ValueError("value must be finite.")
        return number

    @classmethod
    def _normalize_time(cls, raw: Any) -> float:
        value, unit = cls._measurement_parts(raw)
        number = cls._finite_number(value)
        factors = {"ms": 1.0, "millisecond": 1.0, "milliseconds": 1.0,
                   "s": 1000.0, "sec": 1000.0, "second": 1000.0, "seconds": 1000.0,
                   "us": 0.001, "µs": 0.001}
        if unit not in factors:
            raise ValueError(f"unsupported time unit '{unit}'. Use ms, s, or us.")
        result = number * factors[unit]
        if not math.isfinite(result):
            raise ValueError("converted time value must be finite.")
        if result < 0:
            raise ValueError("time values cannot be negative.")
        return round(result, 4)

    @classmethod
    def _normalize_percentage(cls, raw: Any) -> float:
        value, unit = cls._measurement_parts(raw)
        number = cls._finite_number(value)
        if unit in ("%", "percent", "percentage", "pct"):
            result = number
        elif unit in ("fraction", "ratio"):
            if not 0.0 <= number <= 1.0:
                raise ValueError("fraction must be between 0 and 1.")
            result = number * 100.0
        else:
            raise ValueError(f"unsupported percentage unit '{unit}'. Use percent or fraction.")
        if not 0.0 <= result <= 100.0:
            raise ValueError("percentage must be between 0 and 100.")
        return round(result, 4)

    @classmethod
    def _normalize_rate(cls, raw: Any) -> float:
        value, unit = cls._measurement_parts(raw)
        number = cls._finite_number(value)
        factors = {"mbps": 1.0, "gbps": 1000.0, "kbps": 0.001, "bps": 0.000001}
        if unit not in factors:
            raise ValueError(f"unsupported rate unit '{unit}'. Use bps, kbps, Mbps, or Gbps.")
        result = number * factors[unit]
        if not math.isfinite(result):
            raise ValueError("converted rate value must be finite.")
        if result < 0:
            raise ValueError("rate values cannot be negative.")
        return round(result, 4)

    @classmethod
    def _normalize_time_series(cls, raw: Any) -> list[float]:
        value, unit = cls._measurement_parts(raw)
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) < 2:
            raise ValueError("RTT samples must be a list containing at least two numbers.")
        normalized = []
        for sample in value:
            normalized.append(cls._normalize_time({"value": sample, "unit": unit}))
        return normalized

    @staticmethod
    def _deduplicate(items: list[str]) -> list[str]:
        return list(dict.fromkeys(items))


# ==============================================================================
# Pipeline Domain Agent Specification (BaseAgent)
# ==============================================================================

class TelemetryAgent(BaseAgent):
    """Analyzes Layer 3/4 QoS and performance telemetry metrics to detect

    congestion, link saturation, packet drops, transport degradation, and
    bandwidth collapse.
    """

    LATENCY_THRESHOLD_MS: float = 80.0
    PACKET_LOSS_THRESHOLD_PCT: float = 2.0
    JITTER_THRESHOLD_MS: float = 25.0
    UTILIZATION_THRESHOLD_PCT: float = 80.0
    MIN_THROUGHPUT_MBPS: float = 1.0

    _THROUGHPUT_MBPS_UNITS = frozenset({"mbps", "mb/s", "mbit/s", "mbits/s", "dimensionless", ""})
    _THROUGHPUT_GBPS_UNITS = frozenset({"gbps", "gb/s", "gbit/s", "gbits/s"})
    _THROUGHPUT_KBPS_UNITS = frozenset({"kbps", "kb/s", "kbit/s", "kbits/s"})
    _THROUGHPUT_BPS_UNITS = frozenset({"bps", "bit/s", "bits/s"})

    def __init__(self, name: Optional[str] = None) -> None:
        super().__init__(name=name or "TelemetryAgent")

    def _extract_canonical_metrics(
        self,
        metrics: List[TelemetryMetric],
        target_device: Optional[str] = None,
    ) -> Dict[str, TelemetryMetric]:
        """Normalize metric name aliases to canonical telemetry keys.

        Filters specifically for target_device and retains newest timestamped sample.
        """
        mapping: Dict[str, TelemetryMetric] = {}
        for m in metrics:
            if target_device and m.device_id and m.device_id.strip().lower() != target_device.strip().lower():
                continue

            name_clean = m.metric_name.lower().strip()
            canonical_key: Optional[str] = None

            if name_clean in {"rtt_latency_ms", "rtt_latency", "rtt", "latency", "latency_ms"}:
                canonical_key = "latency"
            elif name_clean in {"packet_loss_pct", "packet_loss", "loss_pct", "loss", "packet_loss_percent"}:
                canonical_key = "packet_loss"
            elif name_clean in {"jitter_ms", "jitter"}:
                canonical_key = "jitter"
            elif name_clean in {"link_utilization_pct", "link_utilization", "utilization_pct", "utilization", "bandwidth_utilization"}:
                canonical_key = "utilization"
            elif name_clean in {
                "throughput_mbps", "throughput", "bandwidth_mbps", "rx_bandwidth_mbps",
                "tx_bandwidth_mbps", "rx_throughput_mbps", "tx_throughput_mbps",
                "bandwidth_bps", "throughput_bps", "data_rate_mbps", "bandwidth"
            }:
                canonical_key = "throughput"

            if canonical_key is not None:
                if canonical_key not in mapping or _is_newer(m, mapping[canonical_key]):
                    mapping[canonical_key] = m

        return mapping

    def analyze(self, payload: RawTelemetryPayload) -> AgentFinding:
        """Evaluate telemetry metrics against domain thresholds and multi-metric heuristics."""
        if not payload.metrics:
            limitations: List[str] = []
            if "ingestion_notes" in payload.metadata and payload.metadata["ingestion_notes"]:
                limitations.extend(payload.metadata["ingestion_notes"])
            elif "ingestion_error" in payload.metadata:
                limitations.append(str(payload.metadata["ingestion_error"]))
            elif "validation_error" in payload.metadata:
                limitations.append(str(payload.metadata["validation_error"]))
            else:
                limitations.append("metrics list was empty in payload")

            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis=f"No telemetry metrics provided in payload ({limitations[0] if limitations else 'no metrics'}).",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=limitations,
            )

        telemetry_map = self._extract_canonical_metrics(payload.metrics, target_device=payload.target_device)
        if not telemetry_map:
            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis=f"No recognizable network telemetry metrics found for target device '{payload.target_device}'.",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=["No recognized Layer 3/4 telemetry metrics matched for target device."],
            )

        evidence: List[MetricEvidence] = []
        anomalies: List[str] = []

        # 1. Latency Check
        latency_metric = telemetry_map.get("latency")
        high_latency = False
        if latency_metric is not None:
            high_latency = latency_metric.value > self.LATENCY_THRESHOLD_MS
            evidence.append(
                MetricEvidence(
                    metric=latency_metric.metric_name,
                    value=latency_metric.value,
                    canonical_key="latency",
                    interpretation=(
                        f"Round-trip latency ({latency_metric.value:.2f}{latency_metric.unit}) exceeds SLA threshold "
                        f"({self.LATENCY_THRESHOLD_MS}ms)."
                        if high_latency
                        else f"Round-trip latency ({latency_metric.value:.2f}{latency_metric.unit}) is within nominal limits."
                    ),
                )
            )
            if high_latency:
                anomalies.append("high_latency")

        # 2. Packet Loss Check
        loss_metric = telemetry_map.get("packet_loss")
        high_loss = False
        if loss_metric is not None:
            high_loss = loss_metric.value > self.PACKET_LOSS_THRESHOLD_PCT
            evidence.append(
                MetricEvidence(
                    metric=loss_metric.metric_name,
                    value=loss_metric.value,
                    canonical_key="packet_loss",
                    interpretation=(
                        f"Packet loss ({loss_metric.value:.2f}{loss_metric.unit}) exceeds allowable threshold "
                        f"({self.PACKET_LOSS_THRESHOLD_PCT}%)."
                        if high_loss
                        else f"Packet loss ({loss_metric.value:.2f}{loss_metric.unit}) is nominal."
                    ),
                )
            )
            if high_loss:
                anomalies.append("high_loss")

        # 3. Jitter Check
        jitter_metric = telemetry_map.get("jitter")
        high_jitter = False
        if jitter_metric is not None:
            high_jitter = jitter_metric.value > self.JITTER_THRESHOLD_MS
            evidence.append(
                MetricEvidence(
                    metric=jitter_metric.metric_name,
                    value=jitter_metric.value,
                    canonical_key="jitter",
                    interpretation=(
                        f"Jitter variation ({jitter_metric.value:.2f}{jitter_metric.unit}) exceeds tolerance "
                        f"({self.JITTER_THRESHOLD_MS}ms)."
                        if high_jitter
                        else f"Jitter variation ({jitter_metric.value:.2f}{jitter_metric.unit}) is nominal."
                    ),
                )
            )
            if high_jitter:
                anomalies.append("high_jitter")

        # 4. Utilization Check
        util_metric = telemetry_map.get("utilization")
        high_util = False
        if util_metric is not None:
            high_util = util_metric.value > self.UTILIZATION_THRESHOLD_PCT
            evidence.append(
                MetricEvidence(
                    metric=util_metric.metric_name,
                    value=util_metric.value,
                    canonical_key="utilization",
                    interpretation=(
                        f"Link utilization ({util_metric.value:.2f}{util_metric.unit}) exceeds operational headroom "
                        f"({self.UTILIZATION_THRESHOLD_PCT}%)."
                        if high_util
                        else f"Link utilization ({util_metric.value:.2f}{util_metric.unit}) is within capacity."
                    ),
                )
            )
            if high_util:
                anomalies.append("high_utilization")

        # 5. Throughput / Bandwidth Check
        throughput_metric = telemetry_map.get("throughput")
        low_throughput = False
        if throughput_metric is not None:
            unit_clean = throughput_metric.unit.lower().strip()
            norm_mbps = throughput_metric.value
            if unit_clean in self._THROUGHPUT_GBPS_UNITS:
                norm_mbps = norm_mbps * 1000.0
            elif unit_clean in self._THROUGHPUT_KBPS_UNITS:
                norm_mbps = norm_mbps / 1000.0
            elif unit_clean in self._THROUGHPUT_BPS_UNITS:
                norm_mbps = norm_mbps / 1_000_000.0

            if (high_latency or high_loss or high_util) and norm_mbps <= self.MIN_THROUGHPUT_MBPS:
                low_throughput = True
                anomalies.append("throughput_collapse")

            evidence.append(
                MetricEvidence(
                    metric=throughput_metric.metric_name,
                    value=norm_mbps,
                    canonical_key="throughput",
                    interpretation=(
                        f"Throughput ({norm_mbps:.2f} Mbps) collapsed below minimum threshold ({self.MIN_THROUGHPUT_MBPS} Mbps) under link degradation."
                        if low_throughput
                        else f"Observed throughput bandwidth rate is {norm_mbps:.2f} Mbps."
                    ),
                )
            )

        affected = [payload.target_device] if payload.target_device else []

        if not anomalies:
            has_latency = "latency" in telemetry_map
            has_loss_or_jitter = ("packet_loss" in telemetry_map) or ("jitter" in telemetry_map)

            expected_metrics = ["latency", "packet_loss", "jitter", "utilization"]
            missing_metrics = [m for m in expected_metrics if m not in telemetry_map]
            limitations = [f"Missing telemetry metrics: {', '.join(missing_metrics)}."] if missing_metrics else []

            if not (has_latency and has_loss_or_jitter):
                return AgentFinding(
                    agent_name=self.name,
                    status="insufficient_evidence",
                    hypothesis=f"Insufficient telemetry coverage to confirm normal performance for {payload.target_device}; requires latency and at least one of packet loss or jitter.",
                    confidence=0.45,
                    supporting_evidence=evidence,
                    affected_devices=affected,
                    limitations=limitations or ["Requires latency and at least one of packet loss or jitter."],
                )

            return AgentFinding(
                agent_name=self.name,
                status="healthy",
                hypothesis=f"All monitored network performance metrics on {payload.target_device} operate within standard QoS boundaries.",
                confidence=0.90,
                supporting_evidence=evidence,
                affected_devices=affected,
                limitations=limitations,
            )

        if high_latency and high_util:
            hypothesis = (
                f"Link saturation and congestion detected on {payload.target_device}. "
                "Concurrently high link utilization and queuing delay are causing packet latency spikes."
            )
            confidence = 0.95
        elif high_loss and high_jitter:
            hypothesis = (
                f"Severe transport jitter and packet drop anomalies on {payload.target_device}. "
                "Symptoms indicate wireless interference, bursty buffer overflow, or physical medium instability."
            )
            confidence = 0.90
        elif high_latency and high_loss:
            hypothesis = (
                f"Severe link degradation and congestion on {payload.target_device}. "
                "Elevated round-trip time coupled with active packet dropping suggests queue overflow or throttling."
            )
            confidence = 0.92
        elif high_latency:
            hypothesis = (
                f"Elevated propagation or transmission latency observed on {payload.target_device}. "
                "Path sub-optimality or non-congestive queue delay suspected."
            )
            confidence = 0.75
        elif high_loss:
            hypothesis = (
                f"Active packet loss anomaly on {payload.target_device} exceeding acceptable tolerance."
            )
            confidence = 0.80
        elif high_jitter:
            hypothesis = (
                f"Significant packet delay variation (jitter) observed on {payload.target_device}. "
                "Route flapping or transient queuing suspected."
            )
            confidence = 0.70
        else:
            hypothesis = (
                f"High link utilization approaching saturation on {payload.target_device}."
            )
            confidence = 0.75

        if low_throughput:
            hypothesis += f" Severe bandwidth collapse ({norm_mbps:.2f} Mbps) confirms active throughput starvation."
            confidence = min(0.96, confidence + 0.05)

        return AgentFinding(
            agent_name=self.name,
            status="anomaly_detected",
            hypothesis=hypothesis,
            confidence=confidence,
            supporting_evidence=evidence,
            affected_devices=affected,
            limitations=[],
        )


if __name__ == "__main__":
    demo_input = {
        "incident_id": "INC-001",
        "device_id": "HOSTEL_AP_01",
        "timestamp": "2026-10-31T10:30:00",
        "metrics": {
            "rtt_latency": {"value": 280, "unit": "ms"},
            "packet_loss": {"value": 0.08, "unit": "fraction"},
            "jitter": {"value": 35, "unit": "ms"},
            "link_utilization": {"value": 94, "unit": "percent"},
            "rtt_samples": {"value": [40, 45, 110, 42, 120], "unit": "ms"},
        },
    }
    from json import dumps
    print(dumps(TelemetryPerformanceAgent().analyze(demo_input), indent=2))
