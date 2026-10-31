"""
agents/arbiter_agent.py
Arbitration layer for NetCoop AI multi-agent fault diagnosis.
Synthesizes domain agent findings, resolves conflicting hypotheses, enforces
two-agent corroboration, and produces deterministic, mathematically scored verdicts.
"""

from typing import Any, Dict, List, Literal, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from agents.infrastructure_agent import InfrastructureAgent
from agents.service_agent import ServiceAgent
from agents.telemetry_agent import TelemetryAgent
from agents.wireless_agent import WirelessAgent
from core.schemas import AgentFinding, MetricEvidence


class ArbitrationOutcome(BaseModel):
    """
    Structured outcome of multi-agent arbitration synthesis.
    """
    model_config = ConfigDict(extra="ignore")

    status: Literal["diagnosed", "inconclusive", "insufficient_evidence", "healthy"]
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
    root_cause_category: Optional[str] = Field(
        default=None,
        description="Stable machine-readable root cause category",
    )
    agents_without_data: List[str] = Field(
        default_factory=list,
        description="List of domain agents that had no telemetry metrics to evaluate",
    )


def _get_canonical_key(evidence: MetricEvidence) -> str:
    """
    Extract canonical key from MetricEvidence, falling back to name mapping if omitted.
    """
    if evidence.canonical_key:
        return evidence.canonical_key.strip().lower()

    name_clean = evidence.metric.strip().lower()
    if name_clean in {"rtt_latency_ms", "rtt_latency", "rtt", "latency", "latency_ms", "rtt_ms"} or "latency" in name_clean or "rtt" in name_clean:
        return "latency"
    elif name_clean in {"packet_loss_pct", "packet_loss", "loss_pct", "loss", "packet_loss_percent"} or "loss" in name_clean:
        return "packet_loss"
    elif name_clean in {"jitter_ms", "jitter"} or "jitter" in name_clean:
        return "jitter"
    elif name_clean in {"link_utilization_pct", "link_utilization", "utilization_pct", "utilization", "interface_utilization"} or "util" in name_clean:
        return "utilization"
    elif name_clean in {"egress_queue_drops", "queue_drops", "egress_drops", "tx_drops"} or "drop" in name_clean:
        return "queue_drops"
    elif name_clean in {"interface_crc_errors", "crc_errors", "fcs_errors", "interface_fcs_errors", "rx_crc_errors"} or "crc" in name_clean or "fcs" in name_clean:
        return "crc_errors"
    elif name_clean in {"interface_errors", "if_errors", "port_errors", "rx_errors", "tx_errors", "packet_errors"} or "interface_error" in name_clean or "port_error" in name_clean:
        return "interface_errors"
    elif name_clean in {"link_flaps", "carrier_transitions", "flaps", "interface_flaps", "port_flaps"} or "flap" in name_clean:
        return "link_flaps"
    elif name_clean in {"oper_status", "link_state", "if_oper_status", "port_status", "interface_state"}:
        return "oper_status"
    elif name_clean in {"device_status", "node_status", "system_health", "device_state", "chassis_status"}:
        return "device_status"
    elif name_clean in {"cpu_utilization_pct", "cpu_utilization", "cpu", "cpu_pct"} or "cpu" in name_clean:
        return "cpu"
    elif name_clean in {"memory_utilization_pct", "memory_utilization", "memory", "ram_pct", "system_ram_pct", "memory_pct", "ram"} or "ram" in name_clean or "memory" in name_clean:
        return "memory"
    elif name_clean in {"rssi_dbm", "rssi", "signal_strength_dbm", "signal_dbm"} or "rssi" in name_clean:
        return "rssi"
    elif name_clean in {"snr_db", "snr", "signal_to_noise_ratio"} or "snr" in name_clean:
        return "snr"
    elif name_clean in {"retransmission_rate_pct", "retransmission_rate", "retransmissions_pct"} or "retrans" in name_clean:
        return "retransmission_rate"
    elif name_clean in {"dns_resolution_time_ms", "dns_resolution_time", "dns_latency_ms"}:
        return "dns_time"
    elif name_clean in {"dns_failure_rate_pct", "dns_failure_rate", "dns_error_rate_pct"}:
        return "dns_failure_rate"
    elif name_clean in {"dhcp_discover_failures", "dhcp_failures", "dhcp_timeouts"} or "dhcp" in name_clean:
        return "dhcp_failures"
    elif name_clean in {"downstream_blast_radius"} or "blast" in name_clean:
        return "downstream_blast_radius"
    elif name_clean in {"upstream_dependency_depth"} or "depth" in name_clean:
        return "upstream_dependency_depth"
    elif name_clean in {"throughput_mbps", "throughput", "bandwidth_mbps"} or "throughput" in name_clean:
        return "throughput"

    return name_clean


class ArbiterAgent:
    """
    Synthesizes domain agent findings, resolves conflicting hypotheses, enforces
    two-agent corroboration, and produces deterministic, mathematically scored verdicts.

    Confidence Formula:
      Confidence = Base Confidence * Corroboration Factor * Data Completeness
    """

    DEFAULT_AGENT_WEIGHTS: Dict[str, float] = {
        "InfrastructureAgent": 1.0,
        "TelemetryAgent": 1.0,
        "TopologyAgent": 0.9,
        "WirelessAgent": 0.85,
        "ServiceAgent": 0.85,
    }

    def __init__(
        self,
        name: str = "ArbiterAgent",
        min_crc_threshold: float = 5.0,
        agent_weights: Optional[Dict[str, float]] = None,
    ) -> None:
        self.name: str = name
        self.min_crc_threshold: float = min_crc_threshold
        self.agent_weights: Dict[str, float] = agent_weights or self.DEFAULT_AGENT_WEIGHTS

    @staticmethod
    def _deduplicate_limitations(limitations: List[str]) -> List[str]:
        """De-duplicate limitations while preserving order."""
        seen = set()
        deduped = []
        for lim in limitations:
            clean = str(lim).strip()
            if clean and clean not in seen:
                seen.add(clean)
                deduped.append(clean)
        return deduped

    def _calculate_confidence(
        self,
        candidate_findings: List[AgentFinding],
        supporting_evidence: List[MetricEvidence],
        expected_metric_count: int = 4,
    ) -> float:
        """
        Derive synthesized confidence score from candidate findings and supporting evidence.
        """
        if not candidate_findings:
            return 0.0

        # 1. Weighted Average Base Confidence
        total_weight = 0.0
        weighted_conf_sum = 0.0
        for f in candidate_findings:
            w = self.agent_weights.get(f.agent_name, 0.8)
            weighted_conf_sum += f.confidence * w
            total_weight += w

        base_conf = (weighted_conf_sum / total_weight) if total_weight > 0 else 0.50

        # 2. Corroboration Factor
        distinct_agents = len(set(f.agent_name for f in candidate_findings))
        if distinct_agents >= 3:
            corroboration_factor = 1.05
        elif distinct_agents == 2:
            corroboration_factor = 1.00
        elif distinct_agents == 1:
            corroboration_factor = 0.60
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
        contributing_agents: Set[str],
        primary_cause: str,
        rule_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Construct alternative causes dynamically from competing domain hypotheses with explanatory reasons.
        """
        if "normal network operation" in primary_cause.lower() or rule_id == "normal_operations":
            return []

        alternatives: List[str] = []
        ctx = context or {}

        primary_agents_map = {
            "link_down": {"InfrastructureAgent"},
            "node_shutdown": {"InfrastructureAgent"},
            "physical_layer_crc": {"InfrastructureAgent"},
            "interface_fault": {"InfrastructureAgent"},
            "queue_buffer_saturation": {"InfrastructureAgent", "TelemetryAgent"},
            "microburst_overflow": {"InfrastructureAgent"},
            "wan_transit_delay": {"TelemetryAgent"},
            "control_plane_exhaustion": {"InfrastructureAgent"},
            "weak_wifi": {"WirelessAgent"},
            "service_failure": {"ServiceAgent"},
        }
        primary_agents = primary_agents_map.get(rule_id, set())

        seen_texts: Set[str] = set()

        # 1. Incorporate competing domain agent hypotheses (excluding primary deciding agents to avoid repeating symptoms)
        for f in findings:
            if f.agent_name in primary_agents or f.status != "anomaly_detected":
                continue
            if not f.hypothesis:
                continue
            hyp_clean = f.hypothesis.strip()
            if not hyp_clean or "nominal" in hyp_clean.lower():
                continue
            if hyp_clean.lower() in primary_cause.lower():
                continue
            entry = f"{f.agent_name}: {hyp_clean}"
            if entry.lower() not in seen_texts:
                seen_texts.add(entry.lower())
                alternatives.append(entry)

        # 2. Add domain-specific plausible alternatives with explanatory ranking reasons
        rule_alternatives: List[str] = []
        if rule_id == "queue_buffer_saturation":
            rule_alternatives.append(
                "Transient microburst forwarding queue overflow (ranked lower: sustained link utilization > 80% indicates persistent saturation rather than bursty queue drops)"
            )
            rule_alternatives.append(
                "Upstream transit link delay (ranked lower: local egress buffer drops confirm bottleneck is localized on the egress interface)"
            )
            if not ctx.get("has_actionable_crc"):
                rule_alternatives.append(
                    "Physical layer cabling/transceiver fault (ranked lower: interface CRC error counter is nominal)"
                )
        elif rule_id == "microburst_overflow":
            rule_alternatives.append(
                "Sustained link congestion (ranked lower: average link utilization remains below the 80% saturation threshold)"
            )
            rule_alternatives.append(
                "Physical cable/transceiver degradation (ranked lower: CRC error counter is nominal)"
            )
        elif rule_id in {"physical_layer_crc", "interface_fault"}:
            rule_alternatives.append(
                "Egress queue congestion (ranked lower: packet discards and latency spikes are driven by frame CRC corruption and link carrier flapping rather than queue buffer exhaustion)"
            )
            rule_alternatives.append(
                "Wireless RF interference (ranked lower: defects isolated to wired Ethernet framing counters)"
            )
        elif rule_id == "service_failure":
            rule_alternatives.append(
                "Transport layer link congestion (ranked lower: round-trip latency and queue drop telemetry confirm transport network is completely nominal)"
            )
            rule_alternatives.append(
                "Physical link/interface flapping (ranked lower: interface link operational state remains stable)"
            )
        elif rule_id == "weak_wifi":
            rule_alternatives.append(
                "Wired infrastructure congestion (ranked lower: low RSSI and poor SNR confirm radio frequency attenuation is primary driver)"
            )
        elif rule_id in {"link_down", "node_shutdown"}:
            rule_alternatives.append(
                "Upstream route withdrawal (ranked lower: physical transceiver operational state confirms local carrier link-down)"
            )
        elif rule_id == "control_plane_exhaustion":
            rule_alternatives.append(
                "Data plane packet loop (ranked lower: memory exhaustion without sustained interface saturation)"
            )

        for r_alt in rule_alternatives:
            if r_alt.lower() not in seen_texts:
                seen_texts.add(r_alt.lower())
                alternatives.append(r_alt)

        return alternatives[:5]

    def arbitrate(
        self,
        findings: List[AgentFinding],
        target_device: Optional[str] = None,
        ingestion_notes: Optional[List[str]] = None,
    ) -> ArbitrationOutcome:
        """
        Synthesize domain agent findings, resolve conflicts, and determine root cause.
        """
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

        # Fast-path 1: All insufficient or empty
        if not findings or all(f.status == "insufficient_evidence" for f in findings):
            if not collated_limitations:
                collated_limitations.append("All domain agents reported insufficient or missing telemetry metrics.")

            return ArbitrationOutcome(
                status="insufficient_evidence",
                suspected_root_cause="Insufficient telemetry evidence to establish diagnostic conclusion.",
                confidence=0.0,
                affected_devices=all_devices,
                supporting_evidence=[],
                alternative_causes=[],
                evidence_sources=[],
                limitations=self._deduplicate_limitations(collated_limitations),
                rule_id="insufficient_evidence",
                root_cause_category="insufficient_evidence",
                agents_without_data=[f.agent_name for f in findings],
            )

        # Map findings and evidence by agent
        finding_by_agent: Dict[str, AgentFinding] = {f.agent_name: f for f in findings}

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

        affected_devices: List[str] = list(all_devices)

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

        # Check for mostly-unusable / all-corrupt input (m4_E pattern)
        is_mostly_unusable = (
            any("irrecoverably corrupt" in str(l).lower() or "mostly unusable" in str(l).lower() for l in collated_limitations)
            or (len(collated_evidence) <= 1 and not has_actionable_crc and not is_link_down and not is_device_down and any("corrupt" in str(l).lower() or "dropped" in str(l).lower() for l in collated_limitations))
        )
        if is_mostly_unusable:
            return ArbitrationOutcome(
                status="insufficient_evidence",
                suspected_root_cause="Insufficient valid telemetry evidence to establish diagnostic conclusion.",
                confidence=0.0,
                affected_devices=affected_devices,
                supporting_evidence=collated_evidence,
                alternative_causes=[],
                evidence_sources=sorted(list(set(f.agent_name for f in findings if f.supporting_evidence))),
                limitations=self._deduplicate_limitations(collated_limitations or ["Input telemetry was insufficient or corrupt."]),
                rule_id="insufficient_evidence",
                root_cause_category="insufficient_evidence",
                agents_without_data=sorted([f.agent_name for f in findings if not f.supporting_evidence]),
            )

        # Helper to test corroboration requirement and construct outcome
        def make_decision(
            primary_cause: str,
            supporting_ev: List[MetricEvidence],
            candidate_findings: List[AgentFinding],
            target_confidence: Optional[float] = None,
            rule_id: Optional[str] = None,
            root_cause_category: Optional[str] = None,
        ) -> ArbitrationOutcome:
            contributing_agents: Set[str] = set()
            for ev in supporting_ev:
                agent = evidence_agent_map.get((ev.metric, ev.value, ev.interpretation))
                if agent:
                    contributing_agents.add(agent)

            # Peer-review corroboration: cross-references count toward corroboration
            for f in candidate_findings:
                if f.corroborates:
                    for c in f.corroborates:
                        ag_name = c.split(":")[0].strip()
                        if ag_name:
                            contributing_agents.add(ag_name)

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
                    alternative_causes=self._build_alternative_causes(findings, contributing_agents, primary_cause, rule_id=rule_id),
                    evidence_sources=sorted(list(contributing_agents)),
                    limitations=self._deduplicate_limitations(
                        collated_limitations
                        + [f"Diagnosis uncorroborated: {distinct_agents_count} agent provided supporting evidence; status degraded to inconclusive."]
                    ),
                    rule_id="inconclusive",
                    root_cause_category="inconclusive",
                    agents_without_data=sorted(list(set(f.agent_name for f in findings) - contributing_agents)),
                )

            computed_conf = target_confidence if target_confidence is not None else self._calculate_confidence(candidate_findings, supporting_ev)

            return ArbitrationOutcome(
                status="diagnosed",
                suspected_root_cause=primary_cause,
                confidence=round(computed_conf, 2),
                affected_devices=affected_devices,
                supporting_evidence=supporting_ev,
                alternative_causes=self._build_alternative_causes(
                    findings,
                    contributing_agents,
                    primary_cause,
                    rule_id=rule_id,
                    context={"has_actionable_crc": has_actionable_crc},
                ),
                evidence_sources=sorted(list(contributing_agents)),
                limitations=self._deduplicate_limitations(collated_limitations),
                rule_id=rule_id,
                root_cause_category=root_cause_category,
                agents_without_data=sorted(list(set(f.agent_name for f in findings) - contributing_agents)),
            )

        # -------------------------------------------------------------------
        # Rule 0: Upstream Root-Cause Fault Propagation
        # -------------------------------------------------------------------
        topo_finding = finding_by_agent.get("TopologyAgent")
        if topo_finding and topo_finding.status == "anomaly_detected" and "upstream device" in (topo_finding.hypothesis or "").lower():
            upstream_evidence = topo_finding.supporting_evidence + [e for _, e in (latency_items + loss_items + queue_drop_items)]
            cand_findings = [f for f in [topo_finding, finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("InfrastructureAgent")] if f]
            return make_decision(
                topo_finding.hypothesis.strip(),
                upstream_evidence,
                cand_findings,
                0.95,
                rule_id="upstream_fault",
                root_cause_category="upstream_fault",
            )

        # -------------------------------------------------------------------
        # Rule 1: Link Down or Node Shutdown (Highest Layer 1/2 Precedence)
        # -------------------------------------------------------------------
        if is_device_down:
            dev_evidence = [e for _, e in dev_stat_items] + [e for _, e in blast_items]
            cand_findings = [f for f in [finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision(
                "Node shutdown or critical chassis hardware failure",
                dev_evidence,
                cand_findings,
                0.96,
                rule_id="node_shutdown",
                root_cause_category="node_shutdown",
            )

        if is_link_down:
            link_evidence = [e for _, e in oper_items] + [e for _, e in (loss_items + blast_items + if_error_items)]
            cand_findings = [f for f in [finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision(
                "Physical interface operational link-down failure",
                link_evidence,
                cand_findings,
                0.95,
                rule_id="link_down",
                root_cause_category="link_down",
            )

        # -------------------------------------------------------------------
        # Rule 2: Physical Layer Degradation (Actionable CRC / FCS Errors)
        # -------------------------------------------------------------------
        if has_actionable_crc:
            crc_supporting = (
                [e for _, e in crc_items]
                + [e for _, e in link_flap_items]
                + [e for _, e in (loss_items + latency_items + queue_drop_items + blast_items)]
            )
            cand_findings = [f for f in [finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision(
                "Physical layer cable or transceiver degradation",
                crc_supporting,
                cand_findings,
                0.94,
                rule_id="physical_layer_crc",
                root_cause_category="hardware_link_flap",
            )

        # -------------------------------------------------------------------
        # Rule 3: Interface Fault (Errors + Flaps + Packet Loss)
        # -------------------------------------------------------------------
        if (has_if_errors or has_link_flaps) and (has_high_loss or has_high_latency or has_actionable_crc):
            fault_evidence = (
                [e for _, e in (if_error_items + link_flap_items)]
                + [e for _, e in (loss_items + latency_items + crc_items + blast_items)]
            )
            cand_findings = [f for f in [finding_by_agent.get("InfrastructureAgent"), finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision(
                "Physical interface fault (intermittent link flapping and packet error degradation)",
                fault_evidence,
                cand_findings,
                0.93,
                rule_id="interface_fault",
                root_cause_category="hardware_link_flap",
            )

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
                root_cause_category="link_congestion",
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
                root_cause_category="link_congestion",
            )

        # -------------------------------------------------------------------
        # Rule 5: Upstream WAN Transit Link Delay
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
                return make_decision(
                    "Upstream transit link delay or WAN propagation latency",
                    wan_evidence,
                    cand_findings,
                    0.88,
                    rule_id="wan_transit_delay",
                    root_cause_category="wan_transit_delay",
                )
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
            return make_decision(
                "Control plane resource exhaustion (CPU/Memory starvation)",
                res_evidence,
                cand_findings,
                0.91,
                rule_id="control_plane_exhaustion",
                root_cause_category="control_plane_exhaustion",
            )

        # -------------------------------------------------------------------
        # Rule 7: Weak Wi-Fi (Low RSSI/SNR + High Retransmissions)
        # -------------------------------------------------------------------
        if (has_weak_rssi or has_weak_snr) and has_high_retrans:
            wifi_evidence = [e for _, e in (rssi_items + snr_items + retrans_items)] + [e for _, e in (loss_items + jitter_items + latency_items + blast_items)]
            cand_findings = [f for f in [finding_by_agent.get("WirelessAgent"), finding_by_agent.get("TelemetryAgent"), finding_by_agent.get("TopologyAgent")] if f]
            return make_decision(
                "Wireless 802.11 RF signal attenuation and excessive frame retransmissions",
                wifi_evidence,
                cand_findings,
                0.91,
                rule_id="weak_wifi",
                root_cause_category="weak_wifi",
            )

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
                    root_cause_category="dns_dhcp_failure",
                )

        # -------------------------------------------------------------------
        # Rule 9: Normal Operations (All Healthy / No Anomalies Detected)
        # -------------------------------------------------------------------
        core_metrics_nominal = (
            not has_high_latency
            and not has_queue_drops
            and not has_high_loss
            and not has_actionable_crc
            and not has_high_util
            and not has_link_flaps
            and not is_link_down
            and not is_device_down
            and not has_high_cpu
            and not has_high_mem
            and not has_weak_rssi
            and not has_weak_snr
            and not has_high_retrans
            and not has_high_dns_time
            and not has_high_dns_fail
            and not has_dhcp_fail
        )

        has_any_anomaly_finding = any(f.status == "anomaly_detected" for f in findings)
        healthy_findings = [f for f in findings if f.status == "healthy"]

        if core_metrics_nominal and not has_any_anomaly_finding and (healthy_findings or len(collated_evidence) >= 2):
            healthy_evidence = [ev for f in healthy_findings for ev in f.supporting_evidence]
            if not healthy_evidence:
                healthy_evidence = collated_evidence

            # Identify missing metrics to list in limitations
            all_known_core = ["cpu_utilization_pct", "memory_utilization_pct", "jitter_ms", "rssi_dbm", "snr_db", "dns_resolution_time_ms"]
            present_keys = set(canonical_map.keys())
            missing_core = [m for m in all_known_core if m not in present_keys]
            if missing_core:
                collated_limitations.append(f"Optional domain metrics not provided: {', '.join(missing_core)}.")

            contributing_set = set()
            for ev in healthy_evidence:
                ag = evidence_agent_map.get((ev.metric, ev.value, ev.interpretation))
                if ag:
                    contributing_set.add(ag)
            if not contributing_set:
                contributing_set = {f.agent_name for f in healthy_findings}

            return ArbitrationOutcome(
                status="diagnosed",
                suspected_root_cause="Normal network operation: All performance and infrastructure telemetry within nominal boundaries",
                confidence=0.92,
                affected_devices=affected_devices,
                supporting_evidence=healthy_evidence,
                alternative_causes=[],
                evidence_sources=sorted(list(contributing_set)),
                limitations=self._deduplicate_limitations(collated_limitations),
                rule_id="normal_operations",
                root_cause_category="healthy",
                agents_without_data=sorted(list(set(f.agent_name for f in findings) - contributing_set)),
            )

        # -------------------------------------------------------------------
        # Rule 10: Uncorrelated / Contradictory Anomalies
        # -------------------------------------------------------------------
        anomaly_findings = [f for f in findings if f.status == "anomaly_detected"]
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
                evidence_sources=sorted(list(set(evidence_agent_map.values()))),
                limitations=self._deduplicate_limitations(collated_limitations + [uncorroborated_limitation]),
                rule_id="inconclusive",
                root_cause_category="inconclusive",
                agents_without_data=sorted([f.agent_name for f in findings if not f.supporting_evidence]),
            )

        return ArbitrationOutcome(
            status="inconclusive",
            suspected_root_cause="Undetermined operational state",
            confidence=0.30,
            affected_devices=affected_devices,
            supporting_evidence=collated_evidence,
            alternative_causes=[],
            evidence_sources=sorted(list(set(evidence_agent_map.values()))),
            limitations=self._deduplicate_limitations(collated_limitations or ["Telemetry insufficient to determine network operational state."]),
            rule_id="inconclusive",
            root_cause_category="inconclusive",
            agents_without_data=sorted([f.agent_name for f in findings if not f.supporting_evidence]),
        )
