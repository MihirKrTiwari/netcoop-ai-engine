"""
agents/infrastructure_agent.py
Infrastructure domain agent for NetCoop AI.
Monitors node-level health: CPU, memory, buffer queue drops, and physical interface CRC errors.
"""

from typing import Dict, List, Optional

from agents.base import BaseAgent
from core.schemas import AgentFinding, MetricEvidence, RawTelemetryPayload, TelemetryMetric


class InfrastructureAgent(BaseAgent):
    """
    Analyzes hardware resources, control plane state, forwarding ASIC buffers,
    and Layer 1/2 physical interface health to diagnose node-level faults.
    """

    CPU_THRESHOLD_PCT: float = 85.0
    MEMORY_THRESHOLD_PCT: float = 90.0
    QUEUE_DROPS_THRESHOLD: float = 0.0
    CRC_ERRORS_THRESHOLD: float = 0.0

    def __init__(self, name: Optional[str] = None) -> None:
        super().__init__(name=name or "InfrastructureAgent")

    def _extract_canonical_metrics(self, metrics: List[TelemetryMetric]) -> Dict[str, TelemetryMetric]:
        """
        Normalize metric name variations to canonical infrastructure keys.
        """
        mapping: Dict[str, TelemetryMetric] = {}
        for m in metrics:
            name_clean = m.metric_name.lower().strip()
            if name_clean in {"cpu_utilization_pct", "cpu_utilization", "cpu", "cpu_pct"}:
                mapping["cpu"] = m
            elif name_clean in {"memory_utilization_pct", "memory_utilization", "memory", "ram_pct", "memory_pct"}:
                mapping["memory"] = m
            elif name_clean in {"egress_queue_drops", "queue_drops", "egress_drops", "tx_drops"}:
                mapping["queue_drops"] = m
            elif name_clean in {"interface_crc_errors", "crc_errors", "fcs_errors", "rx_crc_errors"}:
                mapping["crc_errors"] = m
        return mapping

    def analyze(self, payload: RawTelemetryPayload) -> AgentFinding:
        """
        Diagnose infrastructure anomalies distinguishing between control plane exhaustion,
        buffer overflows, and physical layer degradation.
        """
        if not payload.metrics:
            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis="No infrastructure telemetry metrics provided in payload.",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=["Empty metrics list in ingestion payload."],
            )

        infra_map = self._extract_canonical_metrics(payload.metrics)
        if not infra_map:
            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis="No recognizable infrastructure metrics (CPU, RAM, queue drops, CRC errors) found.",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=["No recognized hardware or interface metrics matched."],
            )

        evidence: List[MetricEvidence] = []
        high_cpu = False
        high_memory = False
        buffer_overflow = False
        crc_degradation = False

        # 1. CPU Utilization Check
        cpu_metric = infra_map.get("cpu")
        if cpu_metric is not None:
            high_cpu = cpu_metric.value > self.CPU_THRESHOLD_PCT
            evidence.append(
                MetricEvidence(
                    metric=cpu_metric.metric_name,
                    value=cpu_metric.value,
                    interpretation=(
                        f"CPU utilization ({cpu_metric.value:.1f}%) exceeds critical threshold ({self.CPU_THRESHOLD_PCT}%)."
                        if high_cpu
                        else f"CPU utilization ({cpu_metric.value:.1f}%) is healthy."
                    ),
                )
            )

        # 2. Memory Utilization Check
        mem_metric = infra_map.get("memory")
        if mem_metric is not None:
            high_memory = mem_metric.value > self.MEMORY_THRESHOLD_PCT
            evidence.append(
                MetricEvidence(
                    metric=mem_metric.metric_name,
                    value=mem_metric.value,
                    interpretation=(
                        f"Memory utilization ({mem_metric.value:.1f}%) exceeds safety threshold ({self.MEMORY_THRESHOLD_PCT}%)."
                        if high_memory
                        else f"Memory utilization ({mem_metric.value:.1f}%) is within safe bounds."
                    ),
                )
            )

        # 3. Egress Queue Drops Check
        drops_metric = infra_map.get("queue_drops")
        if drops_metric is not None:
            buffer_overflow = drops_metric.value > self.QUEUE_DROPS_THRESHOLD
            evidence.append(
                MetricEvidence(
                    metric=drops_metric.metric_name,
                    value=drops_metric.value,
                    interpretation=(
                        f"Active egress queue drops detected ({drops_metric.value:.0f} drops), indicating buffer overflow."
                        if buffer_overflow
                        else "No egress queue drops recorded."
                    ),
                )
            )

        # 4. Interface CRC Errors Check
        crc_metric = infra_map.get("crc_errors")
        if crc_metric is not None:
            crc_degradation = crc_metric.value > self.CRC_ERRORS_THRESHOLD
            evidence.append(
                MetricEvidence(
                    metric=crc_metric.metric_name,
                    value=crc_metric.value,
                    interpretation=(
                        f"Physical CRC frame check errors detected ({crc_metric.value:.0f} errors), indicating cabling or optical transceiver degradation."
                        if crc_degradation
                        else "No physical CRC errors detected."
                    ),
                )
            )

        affected = [payload.target_device] if payload.target_device else []

        # Classification heuristics
        if not (high_cpu or high_memory or buffer_overflow or crc_degradation):
            return AgentFinding(
                agent_name=self.name,
                status="healthy",
                hypothesis=f"Hardware and physical interface infrastructure on {payload.target_device} are operating normally.",
                confidence=0.92,
                supporting_evidence=evidence,
                affected_devices=affected,
                limitations=[],
            )

        diagnoses: List[str] = []
        confidence = 0.85

        if crc_degradation and buffer_overflow:
            diagnoses.append(
                f"Concurrent physical layer degradation ({crc_metric.value:.0f} CRC errors) "
                f"and egress buffer overflow ({drops_metric.value:.0f} drops) on {payload.target_device}. "
                "Cabling faults may be causing packet retransmissions leading to downstream queue exhaustion."
            )
            confidence = 0.95
        elif crc_degradation:
            diagnoses.append(
                f"Physical layer cabling or transceiver degradation on {payload.target_device}. "
                f"Accumulation of {crc_metric.value:.0f} CRC errors indicates frame corruption at Layer 1/2."
            )
            confidence = 0.92
        elif buffer_overflow and (high_cpu or high_memory):
            diagnoses.append(
                f"Hardware resource saturation and packet forwarding congestion on {payload.target_device}. "
                "Control plane exhaustion is compounding ASIC buffer queue drops."
            )
            confidence = 0.90
        elif buffer_overflow:
            diagnoses.append(
                f"Forwarding buffer overflow detected on {payload.target_device}. "
                f"Active egress queue drops ({drops_metric.value:.0f}) confirm micro-burst or sustained link congestion."
            )
            confidence = 0.88
        elif high_cpu and high_memory:
            diagnoses.append(
                f"Critical control plane resource exhaustion on {payload.target_device}. "
                f"Both CPU ({cpu_metric.value:.1f}%) and Memory ({mem_metric.value:.1f}%) exceed operational ceilings."
            )
            confidence = 0.94
        elif high_cpu:
            diagnoses.append(
                f"Control plane CPU spike on {payload.target_device} ({cpu_metric.value:.1f}%). "
                "Risk of control plane starvation or routing engine delays."
            )
            confidence = 0.85
        elif high_memory:
            diagnoses.append(
                f"Severe memory exhaustion on {payload.target_device} ({mem_metric.value:.1f}%). "
                "Potential memory leak or oversized routing/state tables."
            )
            confidence = 0.85

        return AgentFinding(
            agent_name=self.name,
            status="anomaly_detected",
            hypothesis=" ".join(diagnoses),
            confidence=confidence,
            supporting_evidence=evidence,
            affected_devices=affected,
            limitations=[],
        )
