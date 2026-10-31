"""
agents/service_agent.py
Service layer diagnostic domain agent for NetCoop AI.
Monitors critical application infrastructure services: DNS latency/failures and DHCP discovery timeouts.
"""

from typing import Dict, List, Optional
from datetime import datetime

from agents.base import BaseAgent
from core.schemas import AgentFinding, MetricEvidence, RawTelemetryPayload, TelemetryMetric
from core.timeutils import is_newer

_is_newer = is_newer


class ServiceAgent(BaseAgent):
    """
    Analyzes core network service metrics to diagnose DNS lookup delays,
    DNS query resolution failures, and DHCP IP lease allocation timeouts.
    """

    # Domain threshold constants
    DNS_RESOLUTION_TIME_THRESHOLD_MS: float = 500.0
    DNS_FAILURE_RATE_THRESHOLD_PCT: float = 5.0
    DHCP_DISCOVER_FAILURES_THRESHOLD: float = 0.0

    # Recognized unit sets
    _MS_UNITS = frozenset({"ms", "msec", "msecs", "millisecond", "milliseconds", "dimensionless", ""})
    _PERCENT_UNITS = frozenset({"%", "pct", "percent", "percentage", "ratio", "fraction"})
    _COUNT_UNITS = frozenset({"count", "failures", "errors", "events", "drops", "dimensionless", ""})

    def __init__(self, name: Optional[str] = None) -> None:
        super().__init__(name=name or "ServiceAgent")

    def _extract_canonical_metrics(
        self,
        metrics: List[TelemetryMetric],
        target_device: Optional[str] = None,
    ) -> Dict[str, TelemetryMetric]:
        """
        Normalize metric name variations to canonical service keys.
        Filters specifically for target_device and retains newest timestamped sample.
        """
        mapping: Dict[str, TelemetryMetric] = {}
        for m in metrics:
            if target_device and m.device_id and m.device_id.strip().lower() != target_device.strip().lower():
                continue

            name_clean = m.metric_name.lower().strip()
            canonical_key: Optional[str] = None

            if name_clean in {
                "dns_resolution_time_ms", "dns_resolution_time", "dns_latency_ms",
                "dns_response_time_ms", "dns_lookup_time_ms", "dns_time_ms", "dns_rtt_ms"
            }:
                canonical_key = "dns_time"
            elif name_clean in {
                "dns_failure_rate_pct", "dns_failure_rate", "dns_error_rate_pct",
                "dns_failure_pct", "dns_failures_pct", "dns_timeout_rate_pct"
            }:
                canonical_key = "dns_failure_rate"
            elif name_clean in {
                "dhcp_discover_failures", "dhcp_failures", "dhcp_timeouts",
                "dhcp_discover_drops", "dhcp_nak_count", "dhcp_lease_failures"
            }:
                canonical_key = "dhcp_failures"

            if canonical_key is not None:
                if canonical_key not in mapping or _is_newer(m, mapping[canonical_key]):
                    mapping[canonical_key] = m

        return mapping

    def analyze(self, payload: RawTelemetryPayload) -> AgentFinding:
        """
        Evaluate core network service metrics against domain thresholds.
        """
        target_device = payload.target_device

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
                hypothesis=f"No service telemetry metrics provided in payload ({limitations[0] if limitations else 'no metrics'}).",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[target_device] if target_device else [],
                limitations=limitations,
            )

        service_map = self._extract_canonical_metrics(payload.metrics, target_device=target_device)
        if not service_map:
            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis=f"No recognizable service metrics (DNS resolution time, DNS failure rate, DHCP failures) found for '{target_device}'.",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[target_device] if target_device else [],
                limitations=["No recognized application service metrics (DNS/DHCP) matched for target device."],
            )

        evidence: List[MetricEvidence] = []
        anomalies: List[str] = []
        limitations: List[str] = []

        # 1. DNS Resolution Time (High if > 500 ms)
        dns_time_metric = service_map.get("dns_time")
        high_dns_time = False
        if dns_time_metric is not None:
            unit_clean = dns_time_metric.unit.lower().strip()
            norm_val = dns_time_metric.value
            if unit_clean in {"s", "sec", "second", "seconds"}:
                norm_val = norm_val * 1000.0

            if unit_clean in self._MS_UNITS or unit_clean in {"s", "sec", "second", "seconds"}:
                high_dns_time = norm_val > self.DNS_RESOLUTION_TIME_THRESHOLD_MS
                evidence.append(
                    MetricEvidence(
                        metric=dns_time_metric.metric_name,
                        value=norm_val,
                        canonical_key="dns_time",
                        interpretation=(
                            f"DNS resolution latency ({norm_val:.1f}ms) exceeds SLA threshold "
                            f"({self.DNS_RESOLUTION_TIME_THRESHOLD_MS}ms), indicating recursive resolver delay or WAN peering congestion."
                            if high_dns_time
                            else f"DNS resolution latency ({norm_val:.1f}ms) is nominal."
                        ),
                    )
                )
                if high_dns_time:
                    anomalies.append("high_dns_resolution_time")
            else:
                limitations.append(f"DNS resolution time unit '{dns_time_metric.unit}' unverified; expected ms.")

        # 2. DNS Failure Rate (High if > 5.0%)
        dns_fail_metric = service_map.get("dns_failure_rate")
        high_dns_fail = False
        if dns_fail_metric is not None:
            unit_clean = dns_fail_metric.unit.lower().strip()
            norm_val = dns_fail_metric.value
            if unit_clean in {"ratio", "fraction"}:
                norm_val = norm_val * 100.0

            if unit_clean in self._PERCENT_UNITS or unit_clean in {"", "dimensionless"}:
                high_dns_fail = norm_val > self.DNS_FAILURE_RATE_THRESHOLD_PCT
                evidence.append(
                    MetricEvidence(
                        metric=dns_fail_metric.metric_name,
                        value=norm_val,
                        canonical_key="dns_failure_rate",
                        interpretation=(
                            f"DNS query failure rate ({norm_val:.1f}%) exceeds threshold "
                            f"({self.DNS_FAILURE_RATE_THRESHOLD_PCT}%), indicating resolver unreachable or zone query timeouts."
                            if high_dns_fail
                            else f"DNS query failure rate ({norm_val:.1f}%) is within acceptable bounds."
                        ),
                    )
                )
                if high_dns_fail:
                    anomalies.append("high_dns_failure_rate")
            else:
                limitations.append(f"DNS failure rate unit '{dns_fail_metric.unit}' unverified; expected percentage.")

        # 3. DHCP Discover Failures (High if > 0)
        dhcp_metric = service_map.get("dhcp_failures")
        high_dhcp_fail = False
        if dhcp_metric is not None:
            unit_clean = dhcp_metric.unit.lower().strip()
            if unit_clean in self._COUNT_UNITS:
                high_dhcp_fail = dhcp_metric.value > self.DHCP_DISCOVER_FAILURES_THRESHOLD
                evidence.append(
                    MetricEvidence(
                        metric=dhcp_metric.metric_name,
                        value=dhcp_metric.value,
                        canonical_key="dhcp_failures",
                        interpretation=(
                            f"Active DHCP discover failures detected ({int(dhcp_metric.value)} drops), "
                            "indicating DHCP pool exhaustion, IP helper misconfiguration, or DHCP server unresponsiveness."
                            if high_dhcp_fail
                            else "No DHCP discover failures detected."
                        ),
                    )
                )
                if high_dhcp_fail:
                    anomalies.append("dhcp_discover_failures")
            else:
                limitations.append(f"DHCP discover failure unit '{dhcp_metric.unit}' unverified; expected count.")

        expected_services = {"dns_time", "dns_failure_rate", "dhcp_failures"}
        missing_keys = sorted(expected_services - service_map.keys())
        if missing_keys:
            limitations.append(f"Missing service metrics: {', '.join(missing_keys)}.")

        affected = [target_device] if target_device else []

        if anomalies:
            base_confidence = 0.90 + min(0.04 * len(anomalies), 0.05)
            return AgentFinding(
                agent_name=self.name,
                status="anomaly_detected",
                hypothesis=f"Core network service degradation detected on '{target_device}': {', '.join(anomalies)}.",
                confidence=round(base_confidence, 2),
                supporting_evidence=evidence,
                affected_devices=affected,
                limitations=limitations,
            )

        return AgentFinding(
            agent_name=self.name,
            status="healthy",
            hypothesis=f"Core network service resolution (DNS and DHCP) for '{target_device}' is nominal.",
            confidence=0.91,
            supporting_evidence=evidence,
            affected_devices=affected,
            limitations=limitations,
        )

    def peer_review(
        self,
        my_finding: AgentFinding,
        all_findings: List[AgentFinding],
    ) -> AgentFinding:
        """
        Cross-reference other agents' findings to verify transport reachability during service faults.
        """
        if my_finding.status != "anomaly_detected":
            return my_finding

        for other in all_findings:
            if other.agent_name == "TelemetryAgent" and other.status == "healthy":
                my_finding.corroborates.append("TelemetryAgent:transport_healthy")
                my_finding.peer_assessments.append(
                    "Service layer failure corroborated with healthy transport layer (no congestion or packet loss)."
                )
        return my_finding
