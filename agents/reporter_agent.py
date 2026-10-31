"""agents/reporter_agent.py

Reporting layer for NetCoop AI multi-agent fault diagnosis.
Transforms arbitrated diagnostic findings into actionable IncidentReports and terminal visualizations.
"""

from typing import Any, Dict, List, Optional, Union
import uuid

from agents.arbiter_agent import ArbitrationOutcome
from agents.incident_reporter import validate_report
from core.schemas import IncidentReport


class ReporterAgent:
    """Synthesizes the final incident report and formulates technical remediation steps.

    Recommendations are driven directly by rule_id on ArbitrationOutcome rather
    than substring matching root-cause text.
    """

    RECOMMENDATIONS_BY_RULE_ID: Dict[str, List[str]] = {
        "microburst_overflow": [
            "Enable dynamic buffer sharing and increase instantaneous burst absorption thresholds on egress port ASIC buffers.",
            "Configure Weighted Random Early Detection (WRED) or Explicit Congestion Notification (ECN) to signal micro-burst onset before tail drop.",
            "Implement traffic pacing and micro-burst egress shaping on high-speed ingress sender interfaces.",
            "Monitor high-frequency queue depth statistics via hardware streaming telemetry (In-band Network Telemetry / INT).",
        ],
        "weak_wifi": [
            "Initiate an RF spectrum analysis scan to detect non-802.11 interference across the 2.4/5GHz bands.",
            "Trigger Dynamic Frequency Selection (DFS) and Radio Resource Management (RRM) to reassign operating channels.",
            "Tune AP transmit power levels to eliminate co-channel overlap and optimize cell edge transitions.",
            "Verify 802.11 client roaming thresholds and minimum basic data rates to prevent sticky clients.",
        ],
        "link_down": [
            "Verify interface administrative status and issue 'no shutdown' if administratively disabled.",
            "Inspect patch cable connection and optical light levels on the local and remote switch ports.",
            "Check remote peer switch interface logs for link partner carrier loss or port-security shutdown.",
            "Inspect transceivers on both link endpoints and verify hardware physical connectivity.",
        ],
        "node_shutdown": [
            "Inspect chassis redundant power supply units (PSUs) and verify power feed status.",
            "Review out-of-band console / IPMI management logs for chassis reboot or power fault codes.",
            "Inspect supervisor engine LED status and verify hardware environmental temperatures.",
            "Verify cooling fan tray operation and check for thermal shutdown triggers.",
        ],
        "interface_fault": [
            "Disable Ethernet auto-negotiation and force speed/duplex settings on both ends of the link.",
            "Inspect fiber connectors for physical contamination using an optical inspection microscope.",
            "Verify transceiver stability and replace suspected failing SFP optics.",
            "Inspect switch port ASIC error counters and evaluate interface loopback diagnostic test.",
        ],
        "service_failure": [
            "Verify authoritative and recursive DNS server response latency and network reachability.",
            "Audit DHCP pool utilization on the local router/DHCP server and extend subnet lease scopes.",
            "Check IP helper-address configuration on the default gateway VLAN interface.",
            "Inspect local firewall rules for dropped UDP port 53 (DNS) and UDP ports 67/68 (DHCP) packets.",
        ],
        "physical_layer_crc": [
            "Inspect, reseat, and clean the optical transceiver (SFP) module on the affected switch interface.",
            "Replace the physical patch cable and verify cable continuity with an OTDR or fluke tester.",
            "Review Digital Optical Monitoring (DOM) Rx/Tx optical power levels against transceiver tolerances.",
            "Inspect the switch interface port for physical pin damage or debris.",
        ],
        "queue_buffer_saturation": [
            "Tune egress queue buffer thresholds and configure Weighted Random Early Detection (WRED) to mitigate tail drops.",
            "Apply egress traffic shaping and rate-limiting on high-bandwidth ingress ports contributing to bursts.",
            "Enable Explicit Congestion Notification (ECN) across transit links to trigger TCP window backoff prior to drops.",
            "Evaluate uplink capacity expansion or configure Link Aggregation Control Protocol (LACP) trunking.",
        ],
        "wan_transit_delay": [
            "Execute bidirectional MTR/traceroutes to isolate the high-latency transit hop along the upstream path.",
            "Verify BGP / OSPF path selection and route policies to bypass congested transit provider links.",
            "Open an SLA escalation inquiry with the upstream carrier/ISP regarding peering link delay.",
            "Verify end-to-end Path MTU Discovery (PMTUD) to avoid unnecessary IP fragmentation.",
        ],
        "control_plane_exhaustion": [
            "Deploy Control Plane Policing (CoPP) to throttle rogue or excessive management/routing traffic to the CPU.",
            "Profile active supervisor engine processes to identify memory leaks or runaway background daemons.",
            "Enable BGP/OSPF route-flap dampening to suppress control plane churn from flapping adjacencies.",
            "Schedule a rolling firmware upgrade to patch known memory leak defects in the network OS.",
        ],
        "upstream_fault": [
            "Coordinate root-cause intervention on the identified upstream transit/distribution node.",
            "Reroute downstream traffic via redundant distribution/core transit paths where available.",
            "Inspect upstream device hardware logs, interface error counters, and supervisor status.",
            "Verify upstream routing protocol adjacencies (OSPF/BGP) and link integrity.",
        ],
        "normal_operations": [
            "No corrective remediation required. Network operational telemetry is within nominal parameters.",
            "Retain baseline metrics in telemetry datastore for future longitudinal trend analysis.",
        ],
        "inconclusive": [
            "Deploy synthetic network probe agents to gather active RTT, loss, and jitter samples.",
            "Enable high-resolution streaming telemetry (gNMI) on target devices during anomaly intervals.",
            "Verify SNMP/gNMI collector connectivity, authentication credentials, and polling intervals.",
            "Schedule an automated packet capture (SPAN/ERSPAN) on the device ingress and egress ports.",
        ],
        "insufficient_evidence": [
            "Deploy synthetic network probe agents to gather active RTT, loss, and jitter samples.",
            "Enable high-resolution streaming telemetry (gNMI) on target devices during anomaly intervals.",
            "Verify SNMP/gNMI collector connectivity, authentication credentials, and polling intervals.",
            "Schedule an automated packet capture (SPAN/ERSPAN) on the device ingress and egress ports.",
        ],
    }

    def __init__(self, name: str = "ReporterAgent") -> None:
        self.name: str = name

    def _determine_recommendations(
        self,
        outcome_or_root_cause: Union[ArbitrationOutcome, str],
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> List[str]:
        """Derive targeted, engineer-ready action items driven directly by rule_id on ArbitrationOutcome.

        Eliminates string substring matching in favor of deterministic rule_id
        dictionary mapping.
        """
        if isinstance(outcome_or_root_cause, ArbitrationOutcome):
            resolved_rule_id = outcome_or_root_cause.rule_id
            resolved_status = outcome_or_root_cause.status
            resolved_cause = outcome_or_root_cause.suspected_root_cause
        else:
            resolved_rule_id = rule_id
            resolved_status = status or "diagnosed"
            resolved_cause = str(outcome_or_root_cause)

        # 1. Primary lookup: directly by rule_id
        if resolved_rule_id and resolved_rule_id in self.RECOMMENDATIONS_BY_RULE_ID:
            return list(self.RECOMMENDATIONS_BY_RULE_ID[resolved_rule_id])

        # 2. Secondary lookup: by status (for inconclusive / insufficient_evidence)
        if resolved_status in self.RECOMMENDATIONS_BY_RULE_ID:
            return list(self.RECOMMENDATIONS_BY_RULE_ID[resolved_status])

        if "normal network operation" in resolved_cause.lower():
            return list(self.RECOMMENDATIONS_BY_RULE_ID["normal_operations"])

        # 3. Default fallback
        return [
            "Conduct targeted diagnostic verification on the affected devices.",
            "Review local system logs (syslog) for concurrent hardware or interface events.",
        ]

    @staticmethod
    def _deduplicate_limitations(limitations: List[str]) -> List[str]:
        """De-duplicate limitation strings while strictly preserving first-seen order."""
        seen = set()
        deduped = []
        for lim in limitations:
            clean = str(lim).strip()
            if clean and clean not in seen:
                seen.add(clean)
                deduped.append(clean)
        return deduped

    def generate_report(
        self,
        arbitration: ArbitrationOutcome,
        incident_id: Optional[str] = None,
        scenario_id: Optional[str] = None,
        ingestion_notes: Optional[List[str]] = None,
    ) -> IncidentReport:
        """Construct a fully validated IncidentReport.

        Args:
            arbitration: Arbitration outcome from ArbiterAgent.
            incident_id: Optional unique incident identifier.
            scenario_id: Optional source scenario name for reference.
            ingestion_notes: Optional ingestion-level notes to append to report
              limitations.

        Returns:
            IncidentReport matching the required challenge schema.
        """
        inc_id = incident_id if incident_id else f"INC-{uuid.uuid4().hex[:8].upper()}"

        # Drive recommendations from rule_id on ArbitrationOutcome
        recommendations = self._determine_recommendations(arbitration)

        # Collate limitations from arbitration and validator notes
        collated_limitations: List[str] = list(arbitration.limitations)
        if ingestion_notes:
            collated_limitations.extend(ingestion_notes)

        deduped_limitations = self._deduplicate_limitations(collated_limitations)

        return IncidentReport(
            incident_id=inc_id,
            status=arbitration.status,
            suspected_root_cause=arbitration.suspected_root_cause,
            confidence=arbitration.confidence,
            affected_devices=arbitration.affected_devices,
            supporting_evidence=arbitration.supporting_evidence,
            alternative_causes=arbitration.alternative_causes,
            recommended_actions=recommendations,
            evidence_sources=arbitration.evidence_sources,
            limitations=deduped_limitations,
        )

    def format_terminal_summary(self, report: IncidentReport) -> str:
        """Generate a high-visibility terminal text summary of the incident report."""
        divider = "=" * 78
        sub_divider = "-" * 78

        status_tag = report.status.upper()
        conf_pct = f"{report.confidence * 100:.1f}%"

        lines = [
            divider,
            f"  NETCOOP AI DIAGNOSTIC REPORT: {report.incident_id}",
            f"  Status: {status_tag} | Confidence: {conf_pct}",
            divider,
            f"Suspected Root Cause:\n  {report.suspected_root_cause}",
            sub_divider,
            f"Affected Devices ({len(report.affected_devices)}):\n  {', '.join(report.affected_devices) if report.affected_devices else 'None'}",
            sub_divider,
            f"Supporting Evidence ({len(report.supporting_evidence)} items):",
        ]

        for idx, ev in enumerate(report.supporting_evidence, 1):
            key_tag = f" [{ev.canonical_key}]" if ev.canonical_key else ""
            lines.append(f"  {idx}. {ev.metric}{key_tag} = {ev.value}: {ev.interpretation}")

        if report.alternative_causes:
            lines.append(sub_divider)
            lines.append(f"Alternative Hypotheses ({len(report.alternative_causes)}):")
            for alt in report.alternative_causes:
                lines.append(f"  - {alt}")

        lines.append(sub_divider)
        lines.append(f"Recommended Actions ({len(report.recommended_actions)}):")
        for idx, act in enumerate(report.recommended_actions, 1):
            lines.append(f"  {idx}. {act}")

        if report.limitations:
            lines.append(sub_divider)
            lines.append(f"Diagnostic Limitations ({len(report.limitations)}):")
            for lim in report.limitations:
                lines.append(f"  * {lim}")

        lines.append(divider)
        return "\n".join(lines)


__all__ = ["ReporterAgent", "validate_report"]
