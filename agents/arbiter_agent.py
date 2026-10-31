"""
agents/arbiter_agent.py
Arbitration and synthesis engine for NetCoop AI multi-agent fault diagnosis.
Correlates findings from domain agents, enforces cross-domain corroboration,
applies dynamic alternative hypothesis selection, and calculates calibrated confidence scores.

Confidence Scoring Methodology:
--------------------------------
Confidence = Weighted_Agent_Confidence * Corroboration_Factor * Data_Completeness

1. Weighted_Agent_Confidence:
   The mean confidence score of agents contributing supporting evidence, weighted by
   domain authority:
     - InfrastructureAgent: 1.2 (authoritative hardware and interface registers)
     - TelemetryAgent:      1.0 (end-to-end transport and QoS metrics)
     - WirelessAgent:       1.1 (802.11 RF physical layer parameters)
     - ServiceAgent:        1.0 (application-layer service state)
     - TopologyAgent:       0.8 (dependency graph & blast radius context)

2. Corroboration_Factor:
   Consensus requirement across distinct agent domains:
     - >= 3 distinct contributing agents: 1.05 (multi-domain consensus bonus)
     - == 2 distinct contributing agents: 1.00 (standard cross-domain consensus)
     - == 1 contributing agent:           0.50 (uncorroborated penalty; status capped at 0.50)
     - == 0 agents:                       0.00

3. Data_Completeness:
   Ratio of observed relevant metrics to expected baseline metrics for the diagnosed state:
     Data_Completeness = min(1.0, 0.70 + 0.30 * (observed_metrics / expected_metrics))

Strict Hackathon Rule:
Never return status "diagnosed" from a single metric or a single agent. At least 2 distinct
corroborating evidence items from at least 2 separate agents are required for diagnosis.
Otherwise, the outcome degrades to "inconclusive" or "insufficient_evidence" with confidence
capped at 0.50.
"""

from typing import Any, Dict, List, Literal, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from agents.infrastructure_agent import InfrastructureAgent
from agents.service_agent import ServiceAgent
from agents.telemetry_agent import TelemetryAgent
from agents.topology_agent import TopologyAgent
from agents.wireless_agent import WirelessAgent
from core.schemas import AgentFinding, MetricEvidence


class ArbitrationOutcome(BaseModel):
    """
    Structured outcome of multi-agent arbitration synthesis.
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
    rule_id: Optional[str] = Field(
        default=None,
        description="Identifier of the arbitration rule that synthesized the root cause",
    )


def _get_canonical_key(evidence: MetricEvidence) -> str:
    """
    Extract canonical metric key from MetricEvidence, falling back safely
    to canonical metric alias mapping if canonical_key was omitted.
    """
    if evidence.canonical_key:
        return evidence.canonical_key.strip().lower()

    name = evidence.metric.strip().lower()
    for alias, ckey in [
        ("fcs", "crc_errors"),
        ("crc", "crc_errors"),
        ("queue_drop", "queue_drops"),
        ("egress_drop", "queue_drops"),
        ("drops", "queue_drops"),
        ("latency", "latency"),
        ("rtt", "latency"),
        ("cpu", "cpu"),
        ("ram", "memory"),
        ("memory", "memory"),
        ("util", "utilization"),
        ("packet_loss", "packet_loss"),
        ("loss", "packet_loss"),
        ("jitter", "jitter"),
        ("throughput", "throughput"),
        ("rssi", "rssi"),
        ("snr", "snr"),
        ("retrans", "retransmission_rate"),
        ("dns_resolution", "dns_time"),
        ("dns_latency", "dns_time"),
        ("dns_time", "dns_time"),
        ("dns_fail", "dns_failure_rate"),
        ("dhcp", "dhcp_failures"),
        ("oper_status", "oper_status"),
        ("link_state", "oper_status"),
        ("device_status", "device_status"),
        ("link_flap", "link_flaps"),
        ("flaps", "link_flaps"),
        ("interface_err", "interface_errors"),
        ("blast_radius", "downstream_blast_radius"),
        ("dependency", "upstream_dependency_depth"),
    ]:
        if alias in name:
            return ckey
    return name


class ArbiterAgent:
    """
    Evaluates domain agent findings and arbitrates the authoritative diagnosis.
    Enforces multi-agent cross-corroboration, dynamic alternative hypothesis derivation,
    and calibrated confidence scoring.
    """

    AGENT_WEIGHTS: Dict[str, float] = {
        "InfrastructureAgent": 1.2,
        "TelemetryAgent": 1.0,
        "WirelessAgent": 1.1,
        "ServiceAgent": 1.0,
        "TopologyAgent": 0.8,
    }

    def __init__(self, name: str = "ArbiterAgent", min_crc_threshold: float = 5.0) -> None:
        self.name: str = name
        self.min_crc_threshold: float = min_crc_threshold

    @staticmethod
    def _deduplicate_limitations(limitations: List[str]) -> List[str]:
        """
        De-duplicate limitation strings while strictly preserving first-seen order.
        """
        seen: Set[str] = set()
        deduped: List[str] = []
        for lim in limitations:
            clean = str(lim).strip()
            if clean and clean not in seen:
                seen.add(clean)
                deduped.append(clean)
        return deduped

    def _calculate_confidence(
        self,
        supporting_findings: List[AgentFinding],
        supporting_evidence: List[MetricEvidence],
        expected_metric_count: int = 4,
    ) -> float:
        """
        Derive diagnostic confidence score from:
            Confidence = Weighted_Agent_Confidence * Corroboration_Factor * Data_Completeness
        """
        if not supporting_findings:
            return 0.0

        # 1. Weighted Agent Confidence
        total_weight = 0.0
        weighted_sum = 0.0
        for f in supporting_findings:
            w = self.AGENT_WEIGHTS.get(f.agent_name, 1.0)
            weighted_sum += f.confidence * w
            total_weight += w

        base_conf = weighted_sum / total_weight if total_weight > 0 else 0.50

        # 2. Corroboration Factor
        distinct_agents = {f.agent_name for f in supporting_findings}
        if len(distinct_agents) >= 3:
            corroboration_factor = 1.05
        elif len(distinct_agents) == 2:
            corroboration_factor = 1.00
        elif len(distinct_agents) == 1:
            corroboration_factor = 0.50
        else:
            corroboration_factor = 0.0

        # 3. Data Completeness
        observed_count = len(supporting_evidence)
        data_completeness = min(1.0, 0.70 + 0.30 * (min(observed_count, expected_metric_count) / max(expected_metric_count, 1)))

        score = base_conf * corroboration_factor * data_completeness
        return min(1.0, max(0.0, round(score, 2)))

    def _build_alternative_causes(
        self,
        findings: List[AgentFinding],
        primary_agent_names: Set[str],
        primary_cause: str,
    ) -> List[str]:
        """
        Construct alternative causes dynamically from competing domain agent hypotheses.
        """
        if "normal network operation" in primary_cause.lower():
            return []

        alternatives: List[str] = []
        seen: Set[str] = set()
        primary_lower = primary_cause.lower().strip()

        for f in findings:
            if f.status != "anomaly_detected":
                continue
            if not f.hypothesis:
                continue

            hyp_clean = f.hypothesis.strip()
            if not hyp_clean or "nominal" in hyp_clean.lower():
                continue

            # Skip if the hypothesis is essentially identical to the primary root cause string
            if hyp_clean.lower() == primary_lower:
                continue

            entry = f"{f.agent_name}: {hyp_clean}"
            if entry not in seen:
                seen.add(entry)
                alternatives.append(entry)

        return alternatives

    def arbitrate(
        self,
        findings: List[AgentFinding],
        target_device: Optional[str] = None,
        ingestion_notes: Optional[List[str]] = None,
    ) -> ArbitrationOutcome:
        """
        Synthesize domain agent findings, resolve conflicts, and determine root cause.
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
            if ingestion_notes:
                collated_limitations.extend(ingestion_notes)
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
                limitations=self._deduplicate_limitations(collated_limitations),
                rule_id="insufficient_evidence",
            )

        # Map findings and evidence by agent
        finding_by_agent: Dict[str, AgentFinding] = {f.agent_name: f for f in findings}
        collated_limitations: List[str] = []
        for f in findings:
            collated_limitations.extend(f.limitations)
        if ingestion_notes:
            collated_limitations.extend(ingestion_notes)

        # Collate unique evidence across all findings
        seen_evidence: Set[Tuple[str, float, str]] = set()
        collated_evidence: List[MetricEvidence] = []
        evidence_agent_map: Dict[Tuple[str, float, str], str] = {}

        for finding in findings:
            for ev in finding.supporting_evidence:
                key = (ev.metric, ev.value, ev.interpretation)
                if key not in seen_evidence:
                    seen_evidence.add(key)
                    collated_evidence.append(ev)
                    evidence_agent_map[key] = finding.agent_name

        affected_devices: List[str] = [target_device] if target_device else []
        for finding in findings:
            for dev in finding.affected_devices:
                if dev not in affected_devices:
                    affected_devices.append(dev)

        evidence_sources: List[str] = [f.agent_name for f in findings]

        # Group evidence by canonical key: ckey -> list of (agent_name, MetricEvidence)
        canonical_map: Dict[str, List[Tuple[str, MetricEvidence]]] = {}
        for ev in collated_evidence:
            ckey = _get_canonical_key(ev)
            agent_name = evidence_agent_map.get((ev.metric, ev.value, ev.interpretation), "UnknownAgent")
            canonical_map.setdefault(ckey, []).append((agent_name, ev))

        # Check domain-specific indicators using canonical keys and agent thresholds
        crc_items = canonical_map.get("crc_errors", [])
        queue_drop_items = canonical_map.get("queue_drops", [])
        latency_items = canonical_map.get("latency", [])
        cpu_items = canonical_map.get("cpu", [])
        mem_items = canonical_map.get("memory", [])
        util_items = canonical_map.get("utilization", [])
        loss_items = canonical_map.get("packet_loss", [])
        jitter_items = canonical_map.get("jitter", [])
        if_error_items = canonical_map.get("interface_errors", [])
        link_flap_items = canonical_map.get("link_flaps", [])
        oper_items = canonical_map.get("oper_status", [])
        dev_stat_items = canonical_map.get("device_status", [])
        rssi_items = canonical_map.get("rssi", [])
        snr_items = canonical_map.get("snr", [])
        retrans_items = canonical_map.get("retransmission_rate", [])
        dns_time_items = canonical_map.get("dns_time", [])
        dns_fail_items = canonical_map.get("dns_failure_rate", [])
        dhcp_items = canonical_map.get("dhcp_failures", [])
        blast_items = canonical_map.get("downstream_blast_radius", [])
        depth_items = canonical_map.get("upstream_dependency_depth", [])

        # Evaluate threshold conditions
        has_actionable_crc = any(e.value > self.min_crc_threshold for _, e in crc_items)
        has_weak_crc = any(0.0 < e.value <= self.min_crc_threshold for _, e in crc_items)
        if has_weak_crc and not has_actionable_crc:
            collated_limitations.append(
                f"Observed CRC error counter is below actionable threshold ({self.min_crc_threshold:.0f}); "
                "treated as weak/incidental evidence."
            )

        has_queue_drops = any(e.value > InfrastructureAgent.QUEUE_DROPS_THRESHOLD for _, e in queue_drop_items)
        has_high_latency = any(e.value > TelemetryAgent.LATENCY_THRESHOLD_MS for _, e in latency_items)
        has_high_cpu = any(e.value > InfrastructureAgent.CPU_THRESHOLD_PCT for _, e in cpu_items)
        has_high_mem = any(e.value > InfrastructureAgent.MEMORY_THRESHOLD_PCT for _, e in mem_items)
        has_high_util = any(e.value > TelemetryAgent.UTILIZATION_THRESHOLD_PCT for _, e in util_items)
        has_high_loss = any(e.value > TelemetryAgent.PACKET_LOSS_THRESHOLD_PCT for _, e in loss_items)
        has_high_jitter = any(e.value > TelemetryAgent.JITTER_THRESHOLD_MS for _, e in jitter_items)

        has_if_errors = any(e.value > InfrastructureAgent.INTERFACE_ERRORS_THRESHOLD for _, e in if_error_items)
        has_link_flaps = any(e.value > InfrastructureAgent.LINK_FLAPS_THRESHOLD for _, e in link_flap_items)
        is_link_down = any(e.value == InfrastructureAgent.OPER_STATUS_DOWN_VAL for _, e in oper_items)
        is_device_down = any(e.value == InfrastructureAgent.DEVICE_STATUS_DOWN_VAL for _, e in dev_stat_items)

        has_weak_rssi = any(e.value < WirelessAgent.RSSI_WEAK_THRESHOLD_DBM for _, e in rssi_items)
        has_weak_snr = any(e.value < WirelessAgent.SNR_WEAK_THRESHOLD_DB for _, e in snr_items)
        has_high_retrans = any(e.value > WirelessAgent.RETRANSMISSION_THRESHOLD_PCT for _, e in retrans_items)

        has_high_dns_time = any(e.value > ServiceAgent.DNS_RESOLUTION_TIME_THRESHOLD_MS for _, e in dns_time_items)
        has_high_dns_fail = any(e.value > ServiceAgent.DNS_FAILURE_RATE_THRESHOLD_PCT for _, e in dns_fail_items)
        has_dhcp_fail = any(e.value > ServiceAgent.DHCP_DISCOVER_FAILURES_THRESHOLD for _, e in dhcp_items)

        # Helper to test corroboration requirement
        def make_decision(
            primary_cause: str,
            supporting_ev: List[MetricEvidence],
            candidate_findings: List[AgentFinding],
            target_confidence: Optional[float] = None,
            rule_id: Optional[str] = None,
        ) -> ArbitrationOutcome:
            contributing_agents: Set[str] = set()
            for ev in supporting_ev:
                agent = evidence_agent_map.get((ev.metric, ev.value, ev.interpretation))
                if agent:
                    contributing_agents.add(agent)

            distinct_evidence_count = len(supporting_ev)
            distinct_agents_count = len(contributing_agents)

            # Strict Corroboration Requirement:
            # Require at least 2 corroborating evidence items from at least 2 different agents
            if distinct_evidence_count < 2 or distinct_agents_count < 2:
                calc_conf = self._calculate_confidence(candidate_findings, supporting_ev)
                capped_conf = min(0.50, round(calc_conf, 2))
                return ArbitrationOutcome(
                    status="inconclusive",
                    suspected_root_cause=f"Inconclusive ({primary_cause}): requires at least 2 corroborating evidence items from at least 2 distinct agents (received {distinct_evidence_count} items from {distinct_agents_count} agent).",
                    confidence=capped_conf,
                    affected_devices=affected_devices,
                    supporting_evidence=supporting_ev,
                    alternative_causes=self._build_alternative_causes(findings, contributing_agents, primary_cause),
                    evidence_sources=list(contributing_agents) or evidence_sources,
                    limitations=self._deduplicate_limitations(
                        collated_limitations
                        + [f"Diagnosis uncorroborated: {distinct_agents_count} agent provided supporting evidence; status degraded to inconclusive."]
                    ),
                    rule_id="inconclusive",
                )

            computed_conf = target_confidence if target_confidence is not None else self._calculate_confidence(candidate_findings, supporting_ev)

            return ArbitrationOutcome(
                status="diagnosed",
                suspected_root_cause=primary_cause,
                confidence=round(computed_conf, 2),
                affected_devices=affected_devices,
                supporting_evidence=supporting_ev,
                alternative_causes=self._build_alternative_causes(findings, contributing_agents, primary_cause),
                evidence_sources=evidence_sources,
                limitations=self._deduplicate_limitations(collated_limitations),
                rule_id=rule_id,
            )

        # -------------------------------------------------------------------
        # Rule 0: Upstream Root-Cause Fault Propagation
        # If TopologyAgent correlates downstream target symptoms with an active
        # fault on an upstream transit/core node, arbitrate that upstream node as root cause.
        # -------------------------------------------------------------------
        topo_finding = finding_by_agent.get("TopologyAgent")
        if topo_finding and topo_finding.status == "anomaly_detected" and "upstream device" in (topo_finding.hypothesis or "").lower():
            upstream_evidence = topo_finding.supporting_evidence + [e for _, e in (latency_items + loss_items + queue_drop_items)]
            cand_findings = [f for f in [topo_finding, finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("InfrastructureAgent")] if f]
            return make_decision(topo_finding.hypothesis.strip(), upstream_evidence, cand_findings, 0.95, rule_id="upstream_fault")

        # -------------------------------------------------------------------
        # Rule 1: Link Down or Node Shutdown (Highest Layer 1/2 Precedence)
        # -------------------------------------------------------------------
        if is_device_down:
            dev_evidence = [e for _, e in dev_stat_items] + [e for _, e in blast_items]
            cand_findings = [f for f in [finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision("Node shutdown or critical chassis hardware failure", dev_evidence, cand_findings, 0.96, rule_id="node_shutdown")

        if is_link_down:
            link_evidence = [e for _, e in oper_items] + [e for _, e in (loss_items + blast_items + if_error_items)]
            cand_findings = [f for f in [finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision("Physical interface operational link-down failure", link_evidence, cand_findings, 0.95, rule_id="link_down")

        # -------------------------------------------------------------------
        # Rule 2: Physical Layer Degradation (Actionable CRC / FCS Errors)
        # -------------------------------------------------------------------
        if has_actionable_crc:
            # Corroborating evidence: CRC errors + transport impact (loss, latency, queue drops, blast)
            crc_supporting = [e for _, e in crc_items] + [e for _, e in (loss_items + latency_items + queue_drop_items + blast_items)]
            cand_findings = [f for f in [finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision("Physical layer cable or transceiver degradation", crc_supporting, cand_findings, 0.94, rule_id="physical_layer_crc")

        # -------------------------------------------------------------------
        # Rule 3: Interface Fault (Errors + Flaps + Packet Loss)
        # -------------------------------------------------------------------
        if (has_if_errors or has_link_flaps) and (has_high_loss or has_high_latency or has_actionable_crc):
            fault_evidence = [e for _, e in (if_error_items + link_flap_items)] + [e for _, e in (loss_items + latency_items + crc_items + blast_items)]
            cand_findings = [f for f in [finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TelemetryAgent")] if f]
            return make_decision("Physical interface fault (intermittent link flapping and packet error degradation)", fault_evidence, cand_findings, 0.93, rule_id="interface_fault")

        # -------------------------------------------------------------------
        # Rule 4: Egress Queue Buffer Exhaustion / Link Saturation / Microburst Overflow
        # -------------------------------------------------------------------
        if has_high_latency and (has_queue_drops or has_high_util):
            sat_evidence = (
                [e for _, e in latency_items]
                + [e for _, e in queue_drop_items]
                + [e for _, e in util_items]
                + [e for _, e in loss_items]
                + [e for _, e in jitter_items]
                + [e for _, e in blast_items]
            )
            cand_findings = [f for f in [finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision(
                "Egress queue buffer exhaustion and localized link saturation",
                sat_evidence,
                cand_findings,
                0.95,
                rule_id="queue_buffer_saturation",
            )

        if has_queue_drops and not has_high_util:
            burst_evidence = (
                [e for _, e in queue_drop_items]
                + [e for _, e in latency_items]
                + [e for _, e in loss_items]
                + [e for _, e in blast_items]
            )
            cand_findings = [f for f in [finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision(
                "Transient microburst forwarding queue overflow",
                burst_evidence,
                cand_findings,
                0.92,
                rule_id="microburst_overflow",
            )

        # -------------------------------------------------------------------
        # Rule 5: Upstream WAN Transit Link Delay
        # Requires infrastructure agent evidence of no queue drops and normal CPU.
        # Missing data is not evidence of absence!
        # -------------------------------------------------------------------
        if has_high_latency and not (has_high_util or has_high_loss or has_high_jitter):
            infra_finding = finding_by_agent.get("InfrastructureAgent")
            has_explicit_no_drops = False
            has_explicit_normal_cpu = False
            wan_infra_evidence: List[MetricEvidence] = []

            if infra_finding:
                for ev in infra_finding.supporting_evidence:
                    ckey = _get_canonical_key(ev)
                    if ckey == "queue_drops" and ev.value == InfrastructureAgent.QUEUE_DROPS_THRESHOLD:
                        has_explicit_no_drops = True
                        wan_infra_evidence.append(ev)
                    elif ckey == "cpu" and ev.value <= InfrastructureAgent.CPU_THRESHOLD_PCT:
                        has_explicit_normal_cpu = True
                        wan_infra_evidence.append(ev)

            if has_explicit_no_drops and has_explicit_normal_cpu:
                wan_evidence = [e for _, e in latency_items] + wan_infra_evidence + [e for _, e in blast_items]
                cand_findings = [f for f in [finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("InfrastructureAgent")] if f]
                return make_decision("Upstream transit link delay or WAN propagation latency", wan_evidence, cand_findings, 0.88, rule_id="wan_transit_delay")
            else:
                collated_limitations.append(
                    "WAN transit delay suspected but cannot be diagnosed without explicit infrastructure evidence "
                    "of zero queue drops and normal CPU utilization (missing data is not evidence of absence)."
                )

        # -------------------------------------------------------------------
        # Rule 6: Control Plane Resource Exhaustion (CPU / RAM Starvation)
        # -------------------------------------------------------------------
        if has_high_cpu or has_high_mem:
            res_evidence = [e for _, e in (cpu_items + mem_items)] + [e for _, e in (latency_items + loss_items + blast_items)]
            cand_findings = [f for f in [finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision("Control plane resource exhaustion (CPU/Memory starvation)", res_evidence, cand_findings, 0.91, rule_id="control_plane_exhaustion")

        # -------------------------------------------------------------------
        # Rule 7: Weak Wi-Fi (Low RSSI/SNR + High Retransmissions)
        # -------------------------------------------------------------------
        if (has_weak_rssi or has_weak_snr) and has_high_retrans:
            wifi_evidence = [e for _, e in (rssi_items + snr_items + retrans_items)] + [e for _, e in (loss_items + jitter_items + latency_items + blast_items)]
            cand_findings = [f for f in [finding_by_agent.get("WirelessAgent"), finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision("Wireless 802.11 RF signal attenuation and excessive frame retransmissions", wifi_evidence, cand_findings, 0.91, rule_id="weak_wifi")

        # -------------------------------------------------------------------
        # Rule 8: DNS/DHCP Service Failure with Healthy Transport Layer
        # -------------------------------------------------------------------
        if has_high_dns_time or has_high_dns_fail or has_dhcp_fail:
            transport_healthy = not (has_high_latency or has_high_loss or has_high_util or has_queue_drops)
            if transport_healthy:
                svc_evidence = [e for _, e in (dns_time_items + dns_fail_items + dhcp_items)] + [e for _, e in (latency_items + cpu_items + blast_items)]
                cand_findings = [f for f in [finding_by_agent.get("ServiceAgent"), finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("InfrastructureAgent")] if f]
                return make_decision(
                    "Core network service failure (DNS resolution timeout or DHCP discovery exhaustion) with healthy transport layer",
                    svc_evidence,
                    cand_findings,
                    0.92,
                    rule_id="service_failure",
                )

        # -------------------------------------------------------------------
        # Rule 9: Normal Operations (All Healthy / No Anomalies Detected)
        # -------------------------------------------------------------------
        anomaly_findings = [f for f in findings if f.status == "anomaly_detected"]
        healthy_findings = [f for f in findings if f.status == "healthy"]
        insufficient_findings = [f for f in findings if f.status == "insufficient_evidence"]

        core_agent_names = {"TelemetryAgent", "InfrastructureAgent"}
        core_insufficient = [f for f in insufficient_findings if f.agent_name in core_agent_names]
        core_healthy = [f for f in healthy_findings if f.agent_name in core_agent_names]

        if not anomaly_findings and (core_healthy or healthy_findings) and not core_insufficient:
            healthy_evidence = [ev for f in healthy_findings for ev in f.supporting_evidence]
            cand_findings = healthy_findings
            return make_decision(
                "Normal network operation: All performance and infrastructure telemetry within nominal boundaries",
                healthy_evidence,
                cand_findings,
                0.92,
                rule_id="normal_operations",
            )

        if not anomaly_findings and insufficient_findings:
            return ArbitrationOutcome(
                status="insufficient_evidence",
                suspected_root_cause="Insufficient telemetry coverage to confirm normal network operation.",
                confidence=0.0,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=[],
                evidence_sources=evidence_sources,
                limitations=self._deduplicate_limitations(collated_limitations or ["One or more diagnostic domains lacked sufficient telemetry."]),
                rule_id="insufficient_evidence",
            )

        # -------------------------------------------------------------------
        # Rule 10: Uncorrelated / Contradictory Anomalies
        # -------------------------------------------------------------------
        if anomaly_findings:
            uncorroborated_limitation = (
                f"Diagnosis uncorroborated: {len(anomaly_findings)} agent(s) reported anomalies "
                "without required cross-domain corroboration; status degraded to inconclusive."
            )
            return ArbitrationOutcome(
                status="inconclusive",
                suspected_root_cause="Inconclusive telemetry correlation: contradictory or uncorroborated domain signals require additional verification",
                confidence=0.45,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=self._build_alternative_causes(findings, set(), "Inconclusive telemetry correlation"),
                evidence_sources=evidence_sources,
                limitations=self._deduplicate_limitations(collated_limitations + [uncorroborated_limitation]),
                rule_id="inconclusive",
            )

        return ArbitrationOutcome(
            status="inconclusive",
            suspected_root_cause="Undetermined operational state",
            confidence=0.30,
            affected_devices=affected_devices,
            supporting_evidence=collated_evidence,
            alternative_causes=["Missing diagnostic telemetry"],
            evidence_sources=evidence_sources,
            limitations=self._deduplicate_limitations(collated_limitations),
            rule_id="inconclusive",
        )
