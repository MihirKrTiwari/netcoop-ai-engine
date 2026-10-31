"""
agents/arbiter_agent.py
Arbitration layer for NetCoop AI multi-agent fault diagnosis.
Correlates findings from domain agents, resolves signal conflicts, and synthesizes root causes.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field

from core.schemas import AgentFinding, MetricEvidence


class ArbitrationOutcome(BaseModel):
    """
    Structured outcome of the arbitration synthesis.
    """
    model_config = ConfigDict(extra="ignore")

    status: Literal["diagnosed", "inconclusive", "insufficient_evidence"]
    suspected_root_cause: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    affected_devices: List[str] = Field(default_factory=list)
    supporting_evidence: List[MetricEvidence] = Field(default_factory=list)
    alternative_causes: List[str] = Field(default_factory=list)
    evidence_sources: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class ArbiterAgent:
    """
    Evaluates domain agent findings and arbitrates the authoritative diagnosis.
    Applies rule-based heuristic precedence and cross-domain correlation.
    """

    def __init__(self, name: str = "ArbiterAgent") -> None:
        self.name: str = name

    def arbitrate(
        self,
        findings: List[AgentFinding],
        target_device: Optional[str] = None,
    ) -> ArbitrationOutcome:
        """
        Synthesize domain agent findings, resolve conflicts, and determine root cause.

        Args:
            findings: List of AgentFinding emitted by domain agents.
            target_device: Primary network device under diagnosis.

        Returns:
            ArbitrationOutcome summarizing diagnostic state, root cause, and evidence.
        """
        if not findings or all(f.status == "insufficient_evidence" for f in findings):
            all_devices: List[str] = [target_device] if target_device else []
            for f in findings:
                for dev in f.affected_devices:
                    if dev not in all_devices:
                        all_devices.append(dev)

            collated_limitations: List[str] = []
            for f in findings:
                collated_limitations.extend(f.limitations)
            if not collated_limitations:
                collated_limitations.append("All domain agents reported insufficient or missing telemetry metrics.")

            return ArbitrationOutcome(
                status="insufficient_evidence",
                suspected_root_cause="Insufficient telemetry evidence to establish diagnostic conclusion.",
                confidence=0.0,
                affected_devices=all_devices,
                supporting_evidence=[],
                alternative_causes=[],
                evidence_sources=[f.agent_name for f in findings],
                limitations=collated_limitations,
            )

        # Collate unique evidence, affected devices, limitations, and source agents
        seen_evidence: set = set()
        collated_evidence: List[MetricEvidence] = []
        for finding in findings:
            for ev in finding.supporting_evidence:
                key = (ev.metric, ev.value, ev.interpretation)
                if key not in seen_evidence:
                    seen_evidence.add(key)
                    collated_evidence.append(ev)

        affected_devices: List[str] = [target_device] if target_device else []
        for finding in findings:
            for dev in finding.affected_devices:
                if dev not in affected_devices:
                    affected_devices.append(dev)

        evidence_sources: List[str] = [f.agent_name for f in findings]
        collated_limitations = []
        for f in findings:
            collated_limitations.extend(f.limitations)

        # Domain findings mapping
        telemetry_f = next((f for f in findings if f.agent_name == "TelemetryAgent"), None)
        infra_f = next((f for f in findings if f.agent_name == "InfrastructureAgent"), None)
        topology_f = next((f for f in findings if f.agent_name == "TopologyAgent"), None)

        # Extract specific evidence indicators
        crc_evidence = [e for e in collated_evidence if "crc" in e.metric.lower() and e.value > 0]
        queue_drop_evidence = [
            e for e in collated_evidence
            if any(k in e.metric.lower() for k in ("queue_drops", "egress_drops", "tx_drops")) and e.value > 0
        ]
        high_latency_evidence = [
            e for e in collated_evidence
            if any(k in e.metric.lower() for k in ("latency", "rtt")) and e.value > 80.0
        ]
        high_cpu_evidence = [e for e in collated_evidence if "cpu" in e.metric.lower() and e.value > 85.0]
        high_mem_evidence = [e for e in collated_evidence if "memory" in e.metric.lower() and e.value > 90.0]
        high_loss_evidence = [e for e in collated_evidence if "loss" in e.metric.lower() and e.value > 2.0]
        high_jitter_evidence = [e for e in collated_evidence if "jitter" in e.metric.lower() and e.value > 25.0]

        has_crc_errors = len(crc_evidence) > 0
        has_queue_drops = len(queue_drop_evidence) > 0
        has_high_latency = len(high_latency_evidence) > 0
        has_high_cpu = len(high_cpu_evidence) > 0
        has_high_mem = len(high_mem_evidence) > 0
        has_high_loss = len(high_loss_evidence) > 0
        has_high_jitter = len(high_jitter_evidence) > 0

        # Heuristic Rule 1: Physical layer CRC errors take highest precedence
        if has_crc_errors:
            return ArbitrationOutcome(
                status="diagnosed",
                suspected_root_cause="Physical layer cable or transceiver degradation",
                confidence=0.94,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=[
                    "Optical transceiver (SFP) signal attenuation or dirty connector",
                    "Electromagnetic interference (EMI) on unshielded cabling",
                    "Forwarding ASIC interface framing hardware failure",
                ],
                evidence_sources=evidence_sources,
                limitations=collated_limitations,
            )

        # Heuristic Rule 2: High Latency AND High Egress Queue Drops -> Localized Buffer Saturation
        if has_high_latency and has_queue_drops:
            return ArbitrationOutcome(
                status="diagnosed",
                suspected_root_cause="Egress queue buffer exhaustion and localized link saturation",
                confidence=0.95,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=[
                    "Bursty microburst traffic exceeding shallow egress ASIC buffers",
                    "Mismatched speed or duplex negotiation on egress port",
                    "Unshaped bulk backup or video streaming traffic contention",
                ],
                evidence_sources=evidence_sources,
                limitations=collated_limitations,
            )

        # Heuristic Rule 3: High Latency BUT Zero Queue Drops AND Low CPU -> Dispute Local Congestion
        if has_high_latency and not has_queue_drops and not has_high_cpu:
            return ArbitrationOutcome(
                status="diagnosed",
                suspected_root_cause="Upstream transit link delay or WAN propagation latency",
                confidence=0.88,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=[
                    "Asymmetric routing or carrier transit route latency",
                    "Intermediate WAN/ISP peering provider queueing",
                    "Distant destination endpoint processing delay",
                ],
                evidence_sources=evidence_sources,
                limitations=collated_limitations,
            )

        # Heuristic Rule 4: Control plane resource exhaustion
        if has_high_cpu or has_high_mem:
            return ArbitrationOutcome(
                status="diagnosed",
                suspected_root_cause="Control plane resource exhaustion (CPU/Memory starvation)",
                confidence=0.91,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=[
                    "Management plane / SNMP polling storm",
                    "Routing protocol churn or BGP route flapping",
                    "Software process memory leak in network operating system",
                ],
                evidence_sources=evidence_sources,
                limitations=collated_limitations,
            )

        # Heuristic Rule 5: Egress queue drops without high latency reading
        if has_queue_drops:
            return ArbitrationOutcome(
                status="diagnosed",
                suspected_root_cause="Transient microburst forwarding queue overflow",
                confidence=0.87,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=[
                    "Incidental client synchronization bursts",
                    "Misconfigured QoS burst sizing on switch port",
                ],
                evidence_sources=evidence_sources,
                limitations=collated_limitations,
            )

        # Heuristic Rule 6: Wireless or transport packet drop anomaly
        if has_high_loss and has_high_jitter:
            return ArbitrationOutcome(
                status="diagnosed",
                suspected_root_cause="Wireless RF interference or transport packet drop anomaly",
                confidence=0.86,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=[
                    "Co-channel interference (CCI) on wireless channels",
                    "Excessive client roaming or poor RSSI coverage boundary",
                ],
                evidence_sources=evidence_sources,
                limitations=collated_limitations,
            )

        # Heuristic Rule 7: All agents report healthy
        healthy_findings = [f for f in findings if f.status == "healthy"]
        if healthy_findings and len(healthy_findings) == len(findings):
            return ArbitrationOutcome(
                status="diagnosed",
                suspected_root_cause="Normal network operation: All performance and infrastructure telemetry within nominal boundaries",
                confidence=0.92,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=[],
                evidence_sources=evidence_sources,
                limitations=collated_limitations,
            )

        # Heuristic Rule 8: Uncorrelated anomalies or conflicting signals -> Inconclusive
        anomaly_findings = [f for f in findings if f.status == "anomaly_detected"]
        if anomaly_findings:
            return ArbitrationOutcome(
                status="inconclusive",
                suspected_root_cause="Inconclusive telemetry correlation: contradictory domain signals require additional verification",
                confidence=0.45,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=[
                    "Intermittent anomaly resolved prior to multi-agent polling window",
                    "Telemetry telemetry gap along intermediate transit hops",
                ],
                evidence_sources=evidence_sources,
                limitations=collated_limitations,
            )

        return ArbitrationOutcome(
            status="inconclusive",
            suspected_root_cause="Undetermined operational state",
            confidence=0.30,
            affected_devices=affected_devices,
            supporting_evidence=collated_evidence,
            alternative_causes=["Missing diagnostic telemetry"],
            evidence_sources=evidence_sources,
            limitations=collated_limitations,
        )
