"""
agents/telemetry_agent.py
Telemetry domain agent for NetCoop AI.
Monitors latency, packet loss, jitter, and link utilization to detect network anomalies.
"""

from typing import Dict, List, Optional

from agents.base import BaseAgent
from core.schemas import AgentFinding, MetricEvidence, RawTelemetryPayload, TelemetryMetric


class TelemetryAgent(BaseAgent):
    """
    Analyzes Layer 3/4 QoS and performance telemetry metrics to detect
    congestion, link saturation, packet drops, and transport degradation.
    """

    LATENCY_THRESHOLD_MS: float = 80.0
    PACKET_LOSS_THRESHOLD_PCT: float = 2.0
    JITTER_THRESHOLD_MS: float = 25.0
    UTILIZATION_THRESHOLD_PCT: float = 80.0

    def __init__(self, name: Optional[str] = None) -> None:
        super().__init__(name=name or "TelemetryAgent")

    def _extract_canonical_metrics(self, metrics: List[TelemetryMetric]) -> Dict[str, TelemetryMetric]:
        """
        Normalize metric name aliases to canonical telemetry keys.
        """
        mapping: Dict[str, TelemetryMetric] = {}
        for m in metrics:
            name_clean = m.metric_name.lower().strip()
            if name_clean in {"rtt_latency_ms", "rtt_latency", "rtt", "latency", "latency_ms"}:
                mapping["latency"] = m
            elif name_clean in {"packet_loss_pct", "packet_loss", "loss_pct", "loss", "packet_loss_percent"}:
                mapping["packet_loss"] = m
            elif name_clean in {"jitter_ms", "jitter"}:
                mapping["jitter"] = m
            elif name_clean in {"link_utilization_pct", "link_utilization", "utilization_pct", "utilization", "bandwidth_utilization"}:
                mapping["utilization"] = m
        return mapping

    def analyze(self, payload: RawTelemetryPayload) -> AgentFinding:
        """
        Evaluate telemetry metrics against domain thresholds and multi-metric heuristics.
        """
        if not payload.metrics:
            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis="No telemetry metrics provided in payload.",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=["Empty metrics list in ingestion payload."],
            )

        telemetry_map = self._extract_canonical_metrics(payload.metrics)
        if not telemetry_map:
            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis="No recognizable network telemetry metrics (latency, loss, jitter, utilization) found.",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=["No recognized Layer 3/4 telemetry metrics matched."],
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

        # Synthesize multi-metric anomaly hypotheses
        affected = [payload.target_device] if payload.target_device else []

        if not anomalies:
            return AgentFinding(
                agent_name=self.name,
                status="healthy",
                hypothesis="All network performance metrics operate within standard QoS boundaries.",
                confidence=0.90,
                supporting_evidence=evidence,
                affected_devices=affected,
                limitations=[],
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

        return AgentFinding(
            agent_name=self.name,
            status="anomaly_detected",
            hypothesis=hypothesis,
            confidence=confidence,
            supporting_evidence=evidence,
            affected_devices=affected,
            limitations=[],
        )
