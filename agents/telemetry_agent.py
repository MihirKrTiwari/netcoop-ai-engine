"""
agents/telemetry_agent.py
Telemetry domain agent for NetCoop AI.
Monitors latency, packet loss, jitter, and link utilization to detect network anomalies.
Filters metrics for target_device and selects newest samples by timestamp.
"""

from typing import Dict, List, Optional
from datetime import datetime

from agents.base import BaseAgent
from core.schemas import AgentFinding, MetricEvidence, RawTelemetryPayload, TelemetryMetric
from core.timeutils import is_newer

_is_newer = is_newer


class TelemetryAgent(BaseAgent):
    """
    Analyzes Layer 3/4 QoS and performance telemetry metrics to detect
    congestion, link saturation, packet drops, transport degradation, and bandwidth collapse.
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
        """
        Normalize metric name aliases to canonical telemetry keys.
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
        """
        Evaluate telemetry metrics against domain thresholds and multi-metric heuristics.
        """
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
