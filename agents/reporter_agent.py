"""
agents/reporter_agent.py
Reporting layer for NetCoop AI multi-agent fault diagnosis.
Transforms arbitrated diagnostic findings into actionable IncidentReports and terminal visualizations.
"""

import uuid
from typing import List, Optional

from agents.arbiter_agent import ArbitrationOutcome
from core.schemas import IncidentReport


class ReporterAgent:
    """
    Synthesizes the final incident report and formulates technical remediation steps.
    """

    def __init__(self, name: str = "ReporterAgent") -> None:
        self.name: str = name

    def _determine_recommendations(self, root_cause: str, status: str) -> List[str]:
        """
        Derive targeted, engineer-ready action items based on the diagnosed root cause.
        """
        cause_lower = root_cause.lower()

        if "physical layer" in cause_lower or "cable" in cause_lower or "crc" in cause_lower or "transceiver" in cause_lower:
            return [
                "Inspect, reseat, and clean the optical transceiver (SFP) module on the affected switch interface.",
                "Replace the physical patch cable and verify cable continuity with an OTDR or fluke tester.",
                "Review Digital Optical Monitoring (DOM) Rx/Tx optical power levels against transceiver tolerances.",
                "Inspect the switch interface port for physical pin damage or debris.",
            ]

        if "egress queue buffer exhaustion" in cause_lower or "localized link saturation" in cause_lower:
            return [
                "Tune egress queue buffer thresholds and configure Weighted Random Early Detection (WRED) to mitigate tail drops.",
                "Apply egress traffic shaping and rate-limiting on high-bandwidth ingress ports contributing to bursts.",
                "Enable Explicit Congestion Notification (ECN) across transit links to trigger TCP window backoff prior to drops.",
                "Evaluate uplink capacity expansion or configure Link Aggregation Control Protocol (LACP) trunking.",
            ]

        if "upstream transit link delay" in cause_lower or "wan propagation" in cause_lower:
            return [
                "Execute bidirectional MTR/traceroutes to isolate the high-latency transit hop along the upstream path.",
                "Verify BGP / OSPF path selection and route policies to bypass congested transit provider links.",
                "Open an SLA escalation inquiry with the upstream carrier/ISP regarding peering link delay.",
                "Verify end-to-end Path MTU Discovery (PMTUD) to avoid unnecessary IP fragmentation.",
            ]

        if "control plane" in cause_lower or "cpu" in cause_lower or "memory" in cause_lower:
            return [
                "Deploy Control Plane Policing (CoPP) to throttle rogue or excessive management/routing traffic to the CPU.",
                "Profile active supervisor engine processes to identify memory leaks or runaway background daemons.",
                "Enable BGP/OSPF route-flap dampening to suppress control plane churn from flapping adjacencies.",
                "Schedule a rolling firmware upgrade to patch known memory leak defects in the network OS.",
            ]

        if "wireless" in cause_lower or "rf interference" in cause_lower:
            return [
                "Initiate an RF spectrum analysis scan to detect non-802.11 interference across the 2.4/5GHz bands.",
                "Trigger Dynamic Frequency Selection (DFS) and Radio Resource Management (RRM) to reassign operating channels.",
                "Tune AP transmit power levels to eliminate co-channel overlap and optimize cell edge transitions.",
            ]

        if "normal network operation" in cause_lower or status == "healthy":
            return [
                "No corrective remediation required. Network operational telemetry is within nominal parameters.",
                "Retain baseline metrics in telemetry datastore for future longitudinal trend analysis.",
            ]

        if status in {"inconclusive", "insufficient_evidence"}:
            return [
                "Deploy synthetic network probe agents to gather active RTT, loss, and jitter samples.",
                "Enable high-resolution streaming telemetry (gNMI) on target devices during anomaly intervals.",
                "Verify SNMP/gNMI collector connectivity, authentication credentials, and polling intervals.",
                "Schedule an automated packet capture (SPAN/ERSPAN) on the device ingress and egress ports.",
            ]

        return [
            "Conduct targeted diagnostic verification on the affected devices.",
            "Review local system logs (syslog) for concurrent hardware or interface events.",
        ]

    def generate_report(
        self,
        arbitration: ArbitrationOutcome,
        incident_id: Optional[str] = None,
        scenario_id: Optional[str] = None,
    ) -> IncidentReport:
        """
        Construct a fully validated IncidentReport.

        Args:
            arbitration: Arbitration outcome from ArbiterAgent.
            incident_id: Optional unique incident identifier.
            scenario_id: Optional source scenario name for reference.

        Returns:
            IncidentReport matching the required challenge schema.
        """
        generated_id = incident_id if incident_id else f"INC-{uuid.uuid4().hex[:8].upper()}"
        recommendations = self._determine_recommendations(arbitration.suspected_root_cause, arbitration.status)

        return IncidentReport(
            incident_id=generated_id,
            status=arbitration.status,
            suspected_root_cause=arbitration.suspected_root_cause,
            confidence=arbitration.confidence,
            affected_devices=arbitration.affected_devices,
            supporting_evidence=arbitration.supporting_evidence,
            alternative_causes=arbitration.alternative_causes,
            recommended_actions=recommendations,
            evidence_sources=arbitration.evidence_sources,
            limitations=arbitration.limitations,
        )

    def format_markdown(self, report: IncidentReport) -> str:
        """
        Generate a publication-grade GitHub-flavored Markdown incident report.
        """
        devices_str = ", ".join(f"`{d}`" for d in report.affected_devices) if report.affected_devices else "None"
        sources_str = ", ".join(f"`{s}`" for s in report.evidence_sources) if report.evidence_sources else "None"

        lines: List[str] = [
            f"# Incident Report: {report.incident_id}",
            "",
            f"- **Status**: `{report.status.upper()}`",
            f"- **Confidence**: `{report.confidence * 100:.1f}%`",
            f"- **Suspected Root Cause**: {report.suspected_root_cause}",
            f"- **Affected Devices**: {devices_str}",
            f"- **Evidence Sources**: {sources_str}",
            "",
            "## Supporting Telemetry Evidence",
            "",
        ]

        if report.supporting_evidence:
            lines.append("| Metric | Value | Interpretation |")
            lines.append("| :--- | :--- | :--- |")
            for ev in report.supporting_evidence:
                lines.append(f"| `{ev.metric}` | `{ev.value}` | {ev.interpretation} |")
        else:
            lines.append("_No quantitative metric evidence recorded._")

        lines.extend(["", "## Recommended Remediation Actions", ""])
        if report.recommended_actions:
            for act in report.recommended_actions:
                lines.append(f"- [ ] {act}")
        else:
            lines.append("_No actions recommended._")

        if report.alternative_causes:
            lines.extend(["", "## Alternative Potential Causes", ""])
            for alt in report.alternative_causes:
                lines.append(f"- {alt}")

        if report.limitations:
            lines.extend(["", "## Limitations & Diagnostic Boundaries", ""])
            for lim in report.limitations:
                lines.append(f"- *{lim}*")

        return "\n".join(lines)

    def format_terminal_table(self, report: IncidentReport) -> str:
        """
        Generate a formatted ASCII terminal summary for CLI output.
        """
        divider = "=" * 80
        sub_divider = "-" * 80
        lines: List[str] = [
            divider,
            f" NETCOOP AI - INCIDENT DIAGNOSIS REPORT [{report.incident_id}]",
            divider,
            f" Status               : {report.status.upper()}",
            f" Confidence           : {report.confidence * 100:.1f}%",
            f" Suspected Root Cause : {report.suspected_root_cause}",
            f" Affected Devices     : {', '.join(report.affected_devices) if report.affected_devices else 'None'}",
            f" Evidence Sources     : {', '.join(report.evidence_sources)}",
            sub_divider,
            " SUPPORTING METRIC EVIDENCE:",
        ]

        for ev in report.supporting_evidence:
            lines.append(f"  • {ev.metric:<28} = {ev.value:<10} | {ev.interpretation}")

        lines.extend([sub_divider, " RECOMMENDED ACTIONS:"])
        for idx, act in enumerate(report.recommended_actions, start=1):
            lines.append(f"  [{idx}] {act}")

        if report.alternative_causes:
            lines.extend([sub_divider, " ALTERNATIVE CAUSES:"])
            for alt in report.alternative_causes:
                lines.append(f"  - {alt}")

        if report.limitations:
            lines.extend([sub_divider, " LIMITATIONS:"])
            for lim in report.limitations:
                lines.append(f"  * {lim}")

        lines.append(divider)
        return "\n".join(lines)
