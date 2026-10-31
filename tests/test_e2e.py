"""
tests/test_e2e.py
End-to-end integration tests for NetCoop AI multi-agent diagnosis pipeline and CLI.
"""

import json
import subprocess
import sys
from pathlib import Path
import pytest

from agents.arbiter_agent import ArbiterAgent, ArbitrationOutcome
from agents.reporter_agent import ReporterAgent
from core.coordinator import NetCoopCoordinator
from core.schemas import AgentFinding, IncidentReport, MetricEvidence, RawTelemetryPayload, TelemetryMetric


class TestCoordinatorE2E:
    """
    End-to-end pipeline execution tests using NetCoopCoordinator.
    """

    def test_link_congestion_scenario_diagnosed(self) -> None:
        coordinator = NetCoopCoordinator()
        scenario_path = Path("scenarios/link_congestion.json")
        assert scenario_path.exists(), "Sample scenario link_congestion.json must exist."

        report: IncidentReport = coordinator.run_from_file(str(scenario_path))

        assert isinstance(report, IncidentReport)
        assert report.status == "diagnosed"
        assert report.suspected_root_cause == "Egress queue buffer exhaustion and localized link saturation"
        assert report.confidence >= 0.90
        assert "HOSTEL_CORE_SW_01" in report.affected_devices
        assert len(report.affected_devices) > 1  # includes downstream APs
        assert len(report.supporting_evidence) >= 4
        assert len(report.recommended_actions) >= 3
        assert len(report.alternative_causes) >= 2
        assert "TelemetryAgent" in report.evidence_sources
        assert "InfrastructureAgent" in report.evidence_sources
        assert "TopologyAgent" in report.evidence_sources

        # Verify key evidence metrics were correlated
        ev_names = {ev.metric for ev in report.supporting_evidence}
        assert "rtt_latency_ms" in ev_names
        assert "egress_queue_drops" in ev_names
        assert "link_utilization_pct" in ev_names

    def test_normal_ops_scenario_diagnosed(self) -> None:
        """
        Verify that a completely healthy baseline scenario is diagnosed as normal operations (92%).
        """
        coordinator = NetCoopCoordinator()
        scenario_path = Path("scenarios/normal_ops.json")
        assert scenario_path.exists(), "Sample scenario normal_ops.json must exist."

        report: IncidentReport = coordinator.run_from_file(str(scenario_path))

        assert isinstance(report, IncidentReport)
        assert report.status == "diagnosed"
        assert "Normal network operation" in report.suspected_root_cause
        assert report.confidence >= 0.90
        assert "edge-ap-01" in report.affected_devices
        assert len(report.alternative_causes) == 0
        assert len(report.recommended_actions) >= 1

    def test_healthy_device_missing_from_topology_diagnosed(self) -> None:
        """
        Verify that an unmapped healthy device is cleanly diagnosed as normal operations,
        recording an appropriate limitation rather than degrading to inconclusive.
        """
        payload = RawTelemetryPayload(
            scenario_id="healthy_unmapped_edge",
            target_device="UNKNOWN_CAMPUS_LEAF_99",
            metrics=[
                TelemetryMetric(
                    metric_name="rtt_latency_ms",
                    value=12.0,
                    unit="ms",
                    device_id="UNKNOWN_CAMPUS_LEAF_99",
                ),
                TelemetryMetric(
                    metric_name="packet_loss_pct",
                    value=0.0,
                    unit="%",
                    device_id="UNKNOWN_CAMPUS_LEAF_99",
                ),
                TelemetryMetric(
                    metric_name="cpu_utilization_pct",
                    value=20.0,
                    unit="%",
                    device_id="UNKNOWN_CAMPUS_LEAF_99",
                ),
                TelemetryMetric(
                    metric_name="egress_queue_drops",
                    value=0.0,
                    unit="count",
                    device_id="UNKNOWN_CAMPUS_LEAF_99",
                ),
            ],
        )

        coordinator = NetCoopCoordinator()
        report = coordinator.run(payload)

        assert isinstance(report, IncidentReport)
        assert report.status == "diagnosed"
        assert "Normal network operation" in report.suspected_root_cause
        assert report.confidence >= 0.90
        assert "UNKNOWN_CAMPUS_LEAF_99" in report.affected_devices
        assert any("unmapped in topology" in lim.lower() for lim in report.limitations)

    def test_malformed_data_scenario_resilience(self) -> None:
        coordinator = NetCoopCoordinator()
        scenario_path = Path("scenarios/malformed_data.json")
        assert scenario_path.exists(), "Sample scenario malformed_data.json must exist."

        report: IncidentReport = coordinator.run_from_file(str(scenario_path))

        assert isinstance(report, IncidentReport)
        assert report.status == "diagnosed"
        assert report.suspected_root_cause == "Egress queue buffer exhaustion and localized link saturation"
        assert report.confidence >= 0.90
        assert "HOSTEL_CORE_SW_01" in report.affected_devices


class TestArbiterConflictResolution:
    """
    Test suite validating explicit Arbiter conflict resolution rules and metric alias mapping.
    """

    def test_link_saturation_with_high_utilization_and_zero_drops(self) -> None:
        """
        High latency + high link utilization must be diagnosed as link saturation at 95% confidence,
        not misclassified as WAN propagation delay.
        """
        payload = RawTelemetryPayload(
            scenario_id="saturation_no_drops_test",
            target_device="edge-ap-01",
            metrics=[
                TelemetryMetric(
                    metric_name="rtt_latency_ms",
                    value=150.0,
                    unit="ms",
                    device_id="edge-ap-01",
                ),
                TelemetryMetric(
                    metric_name="link_utilization_pct",
                    value=97.0,
                    unit="%",
                    device_id="edge-ap-01",
                ),
                TelemetryMetric(
                    metric_name="egress_queue_drops",
                    value=0.0,
                    unit="count",
                    device_id="edge-ap-01",
                ),
                TelemetryMetric(
                    metric_name="cpu_utilization_pct",
                    value=30.0,
                    unit="%",
                    device_id="edge-ap-01",
                ),
            ],
        )

        coordinator = NetCoopCoordinator()
        report = coordinator.run(payload)

        assert report.status == "diagnosed"
        assert report.suspected_root_cause == "Egress queue buffer exhaustion and localized link saturation"
        assert report.confidence == 0.95

    def test_arbiter_recognizes_fcs_and_ram_aliases(self) -> None:
        """
        Ensure Arbiter recognizes fcs_errors (CRC alias) and ram_pct (memory alias)
        and correctly arbitrates physical degradation and control plane exhaustion.
        """
        arbiter = ArbiterAgent()

        fcs_finding = AgentFinding(
            agent_name="InfrastructureAgent",
            status="anomaly_detected",
            hypothesis="CRC errors observed.",
            confidence=0.92,
            supporting_evidence=[
                MetricEvidence(
                    metric="interface_fcs_errors",
                    value=15.0,
                    interpretation="FCS frame errors detected.",
                )
            ],
            affected_devices=["test-switch"],
        )
        # Uncorroborated single-agent finding degrades to inconclusive with confidence capped <= 0.50
        outcome_fcs_alone = arbiter.arbitrate([fcs_finding], target_device="test-switch")
        assert outcome_fcs_alone.status == "inconclusive"
        assert outcome_fcs_alone.confidence <= 0.50

        # Cross-agent corroboration achieves diagnosed status
        loss_corroboration = AgentFinding(
            agent_name="TelemetryAgent",
            status="anomaly_detected",
            hypothesis="Packet drops observed.",
            confidence=0.89,
            supporting_evidence=[
                MetricEvidence(
                    metric="packet_loss_pct",
                    value=4.5,
                    interpretation="Packet loss due to corrupted frames.",
                    canonical_key="packet_loss",
                )
            ],
            affected_devices=["test-switch"],
        )
        outcome_fcs = arbiter.arbitrate([fcs_finding, loss_corroboration], target_device="test-switch")
        assert outcome_fcs.status == "diagnosed"
        assert "Physical layer cable or transceiver degradation" in outcome_fcs.suspected_root_cause

        ram_finding = AgentFinding(
            agent_name="InfrastructureAgent",
            status="anomaly_detected",
            hypothesis="High RAM observed.",
            confidence=0.91,
            supporting_evidence=[
                MetricEvidence(
                    metric="system_ram_pct",
                    value=96.0,
                    interpretation="RAM memory exhaustion.",
                )
            ],
            affected_devices=["test-switch"],
        )
        latency_corroboration = AgentFinding(
            agent_name="TelemetryAgent",
            status="anomaly_detected",
            hypothesis="Latency spikes observed.",
            confidence=0.88,
            supporting_evidence=[
                MetricEvidence(
                    metric="rtt_latency_ms",
                    value=120.0,
                    interpretation="RTT latency degradation under CPU load.",
                    canonical_key="latency",
                )
            ],
            affected_devices=["test-switch"],
        )
        outcome_ram = arbiter.arbitrate([ram_finding, latency_corroboration], target_device="test-switch")
        assert outcome_ram.status == "diagnosed"
        assert "Control plane resource exhaustion" in outcome_ram.suspected_root_cause

    def test_dispute_local_congestion_when_infra_is_clear(self) -> None:
        """
        If Telemetry reports high latency but Infrastructure reports zero queue drops and low CPU,
        dispute local congestion and prioritize upstream transit link delay.
        """
        payload = RawTelemetryPayload(
            scenario_id="scen_upstream_delay",
            target_device="edge-ap-01",
            metrics=[
                TelemetryMetric(
                    metric_name="rtt_latency_ms",
                    value=150.0,
                    unit="ms",
                    device_id="edge-ap-01",
                ),
                TelemetryMetric(
                    metric_name="egress_queue_drops",
                    value=0.0,
                    unit="count",
                    device_id="edge-ap-01",
                ),
                TelemetryMetric(
                    metric_name="cpu_utilization_pct",
                    value=30.0,
                    unit="%",
                    device_id="edge-ap-01",
                ),
            ],
        )

        coordinator = NetCoopCoordinator()
        report = coordinator.run(payload)

        assert report.status == "diagnosed"
        assert report.suspected_root_cause == "Upstream transit link delay or WAN propagation latency"
        assert report.confidence >= 0.85

    def test_prioritize_crc_errors_over_congestion(self) -> None:
        """
        If CRC errors are present, prioritize Physical layer cable or transceiver degradation.
        """
        payload = RawTelemetryPayload(
            scenario_id="scen_crc_fault",
            target_device="acc-sw-01",
            metrics=[
                TelemetryMetric(
                    metric_name="rtt_latency_ms",
                    value=130.0,
                    unit="ms",
                    device_id="acc-sw-01",
                ),
                TelemetryMetric(
                    metric_name="egress_queue_drops",
                    value=45.0,
                    unit="count",
                    device_id="acc-sw-01",
                ),
                TelemetryMetric(
                    metric_name="interface_crc_errors",
                    value=180.0,
                    unit="count",
                    device_id="acc-sw-01",
                ),
            ],
        )

        coordinator = NetCoopCoordinator()
        report = coordinator.run(payload)

        assert report.status == "diagnosed"
        assert report.suspected_root_cause == "Physical layer cable or transceiver degradation"
        assert report.confidence >= 0.90


class TestCliExecution:
    """
    Subprocess CLI invocation tests for main.py.
    """

    def test_cli_link_congestion_stdout_json(self) -> None:
        cmd = [
            sys.executable,
            "main.py",
            "--scenario",
            "scenarios/link_congestion.json",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        assert result.returncode == 0, f"CLI exited with non-zero code. Stderr: {result.stderr}"

        # Ensure stdout is valid JSON matching IncidentReport schema
        parsed_json = json.loads(result.stdout)
        report = IncidentReport.model_validate(parsed_json)

        assert report.status == "diagnosed"
        assert report.suspected_root_cause == "Egress queue buffer exhaustion and localized link saturation"
        assert "HOSTEL_CORE_SW_01" in report.affected_devices

    def test_cli_output_to_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "incident_output.json"
        cmd = [
            sys.executable,
            "main.py",
            "--scenario",
            "scenarios/link_congestion.json",
            "--output",
            str(out_file),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        assert result.returncode == 0
        assert out_file.exists(), "Output JSON file was not written."

        with open(out_file, "r", encoding="utf-8") as f:
            file_data = json.load(f)

        report = IncidentReport.model_validate(file_data)
        assert report.status == "diagnosed"
        assert report.confidence >= 0.90

    def test_cli_nonexistent_scenario_error_code(self) -> None:
        cmd = [
            sys.executable,
            "main.py",
            "--scenario",
            "scenarios/nonexistent_file.json",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        assert result.returncode == 1
        assert "Scenario file not found" in result.stderr


class TestIngestionNotesAndResilience:
    """
    Test suite verifying ingestion notes visibility in IncidentReport.limitations,
    agent fault isolation (try/except wrapper), de-duplication, file ingestion resilience,
    and multi-agent end-to-end diagnosis of wireless and service anomalies.
    """

    def test_ingestion_notes_appear_in_incident_report_limitations(self) -> None:
        coordinator = NetCoopCoordinator(parallel_execution=False)
        payload = {
            "scenario": "edge_conversion_test",
            "device": "HOSTEL_CORE_SW_01",
            "schema_version": "v9.9.custom",
            "metrics": [
                {
                    "metric_name": "rtt_latency_ms",
                    "value": "0.150",
                    "unit": "s",
                },
                {
                    "metric_name": "link_utilization_pct",
                    "value": 92.0,
                    "unit": "%",
                },
                {
                    "name": "packet_loss_pct",
                    "val": "0.05",
                    "unit": "ratio",
                },
                {
                    "metric_name": "bad_counter",
                    "value": "NOT_A_NUMBER",
                },
            ],
        }

        report = coordinator.run(payload)

        assert isinstance(report, IncidentReport)
        assert any("unknown schema version" in lim.lower() for lim in report.limitations)
        assert any("renamed field" in lim.lower() for lim in report.limitations)
        assert any("unit conversion" in lim.lower() for lim in report.limitations)
        assert any("dropped metric" in lim.lower() for lim in report.limitations)
        assert len(report.limitations) == len(set(report.limitations))

    def test_dict_metrics_converted_and_noted_in_report_limitations(self) -> None:
        coordinator = NetCoopCoordinator(parallel_execution=False)
        payload = {
            "scenario_id": "dict_metrics_scenario",
            "target_device": "HOSTEL_CORE_SW_01",
            "metrics": {
                "rtt_latency_ms": 140.0,
                "link_utilization_pct": 95.0,
                "egress_queue_drops": 120.0,
            },
        }

        report = coordinator.run(payload)

        assert isinstance(report, IncidentReport)
        assert report.status == "diagnosed"
        assert report.suspected_root_cause == "Egress queue buffer exhaustion and localized link saturation"
        assert any("metrics field was a dict and was converted" in lim for lim in report.limitations)
        assert not any("Empty metrics list" in lim for lim in report.limitations)

    def test_non_dict_payload_shows_real_cause_in_limitations(self) -> None:
        coordinator = NetCoopCoordinator(parallel_execution=False)
        report = coordinator.run("this is a raw string, not JSON or dict")

        assert isinstance(report, IncidentReport)
        assert report.status == "insufficient_evidence"
        assert any("malformed json" in lim.lower() or "payload was not a dict" in lim.lower() for lim in report.limitations)
        assert not any("Empty metrics list" in lim for lim in report.limitations)

        report_int = coordinator.run(12345)
        assert report_int.status == "insufficient_evidence"
        assert any("payload was not a dict" in lim.lower() for lim in report_int.limitations)
        assert not any("Empty metrics list" in lim for lim in report_int.limitations)

    def test_limitations_are_deduplicated(self) -> None:
        coordinator = NetCoopCoordinator()
        duplicate_limitation = "Duplicated sensor timeout warning"
        payload = {
            "scenario_id": "dedup_test",
            "target_device": "edge-ap-01",
            "metadata": {
                "ingestion_notes": [duplicate_limitation, duplicate_limitation, duplicate_limitation],
            },
            "metrics": [
                {"metric_name": "rtt_latency_ms", "value": 15.0, "unit": "ms"},
                {"metric_name": "packet_loss_pct", "value": 0.1, "unit": "%"},
                {"metric_name": "cpu_utilization_pct", "value": 25.0, "unit": "%"},
            ],
        }

        report = coordinator.run(payload)
        occurrences = [lim for lim in report.limitations if lim == duplicate_limitation]
        assert len(occurrences) == 1
        assert len(report.limitations) == len(set(report.limitations))

    def test_agent_failure_does_not_crash_coordinator(self) -> None:
        class FailingAgent:
            name = "CrashingAgent"

            def analyze(self, payload: RawTelemetryPayload) -> AgentFinding:
                raise RuntimeError("Hardware ASIC driver crashed unexpectedly")

        coordinator = NetCoopCoordinator(
            telemetry_agent=FailingAgent(),  # type: ignore[arg-type]
            parallel_execution=False,
        )

        payload = {
            "scenario_id": "agent_failure_test",
            "target_device": "edge-ap-01",
            "metrics": [
                {"metric_name": "cpu_utilization_pct", "value": 30.0, "unit": "%"},
            ],
        }

        report = coordinator.run(payload)
        assert isinstance(report, IncidentReport)
        assert any("Agent execution error in CrashingAgent: Hardware ASIC driver crashed unexpectedly" in lim for lim in report.limitations)

    def test_run_from_file_malformed_json_resilience(self, tmp_path: Path) -> None:
        malformed_file = tmp_path / "broken.json"
        malformed_file.write_text("{ scenario_id: 'broken' unquoted JSON ", encoding="utf-8")

        coordinator = NetCoopCoordinator()
        report = coordinator.run_from_file(str(malformed_file))

        assert isinstance(report, IncidentReport)
        assert report.status == "insufficient_evidence"
        assert report.confidence == 0.0
        assert any("malformed json" in lim.lower() for lim in report.limitations)

    def test_run_from_file_empty_file_resilience(self, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("   \n\t  ", encoding="utf-8")

        coordinator = NetCoopCoordinator()
        report = coordinator.run_from_file(str(empty_file))

        assert isinstance(report, IncidentReport)
        assert report.status == "insufficient_evidence"
        assert report.confidence == 0.0
        assert any("empty" in lim.lower() for lim in report.limitations)

    def test_run_from_file_utf8_bom_resilience(self, tmp_path: Path) -> None:
        bom_file = tmp_path / "bom_scenario.json"
        content = json.dumps({
            "scenario_id": "bom_test",
            "target_device": "HOSTEL_CORE_SW_01",
            "metrics": [
                {"metric_name": "rtt_latency_ms", "value": 140.0, "unit": "ms"},
                {"metric_name": "link_utilization_pct", "value": 95.0, "unit": "%"},
                {"metric_name": "egress_queue_drops", "value": 150.0, "unit": "count"},
                {"metric_name": "cpu_utilization_pct", "value": 45.0, "unit": "%"},
            ],
        })
        bom_file.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))

        coordinator = NetCoopCoordinator()
        report = coordinator.run_from_file(str(bom_file))

        assert isinstance(report, IncidentReport)
        assert report.status == "diagnosed"
        assert report.suspected_root_cause == "Egress queue buffer exhaustion and localized link saturation"
        assert report.confidence >= 0.90

    def test_coordinator_end_to_end_wireless_anomaly(self) -> None:
        coordinator = NetCoopCoordinator()
        payload = {
            "scenario_id": "wifi_e2e_test",
            "target_device": "edge-ap-01",
            "metrics": [
                {"metric_name": "rssi_dbm", "value": -84.0, "unit": "dBm"},
                {"metric_name": "snr_db", "value": 8.0, "unit": "dB"},
                {"metric_name": "retransmission_rate_pct", "value": 22.0, "unit": "%"},
            ],
        }

        report = coordinator.run(payload)
        assert isinstance(report, IncidentReport)
        assert report.status == "diagnosed"
        assert "Wireless" in report.suspected_root_cause or "RF" in report.suspected_root_cause
        assert "WirelessAgent" in report.evidence_sources
        assert report.confidence >= 0.90

    def test_coordinator_end_to_end_service_anomaly(self) -> None:
        coordinator = NetCoopCoordinator(parallel_execution=False)
        payload = {
            "scenario_id": "service_e2e_test",
            "target_device": "HOSTEL_CORE_SW_01",
            "metrics": [
                {"metric_name": "dns_resolution_time_ms", "value": 750.0, "unit": "ms"},
                {"metric_name": "dhcp_discover_failures", "value": 15.0, "unit": "count"},
            ],
        }

        report = coordinator.run(payload)
        assert isinstance(report, IncidentReport)
        assert report.status == "diagnosed"
        assert "DNS" in report.suspected_root_cause or "DHCP" in report.suspected_root_cause or "service" in report.suspected_root_cause.lower()
        assert "ServiceAgent" in report.evidence_sources
        assert report.confidence >= 0.90


class TestArbiterAgentAdvancedRules:
    """
    Validates all arbitration rules, multi-agent corroboration enforcement,
    weak CRC thresholding, and dynamic hypothesis arbitration.
    """

    def test_uncorroborated_single_agent_evidence_degrades_to_inconclusive(self) -> None:
        """
        Hackathon Rule: Never return diagnosed from a single metric or single agent.
        Must degrade to inconclusive with confidence capped <= 0.50.
        """
        arbiter = ArbiterAgent()

        single_finding = AgentFinding(
            agent_name="TelemetryAgent",
            status="anomaly_detected",
            hypothesis="Severe packet drops on edge link.",
            confidence=0.95,
            supporting_evidence=[
                MetricEvidence(
                    metric="packet_loss_pct",
                    value=8.5,
                    interpretation="Packet loss is excessive.",
                    canonical_key="packet_loss",
                )
            ],
            affected_devices=["isolated-node"],
        )

        outcome = arbiter.arbitrate([single_finding], target_device="isolated-node")
        assert outcome.status == "inconclusive"
        assert outcome.confidence <= 0.50
        assert any("Diagnosis uncorroborated" in lim for lim in outcome.limitations)

    def test_wan_latency_requires_explicit_infra_evidence_missing_data_fails(self) -> None:
        """
        WAN transit delay rule requires explicit infrastructure evidence of zero queue drops
        and normal CPU. Missing data is NOT evidence of absence.
        """
        arbiter = ArbiterAgent()

        telemetry_high_latency = AgentFinding(
            agent_name="TelemetryAgent",
            status="anomaly_detected",
            hypothesis="Transit latency spike observed.",
            confidence=0.90,
            supporting_evidence=[
                MetricEvidence(
                    metric="rtt_latency_ms",
                    value=165.0,
                    interpretation="RTT latency is 165ms.",
                    canonical_key="latency",
                )
            ],
            affected_devices=["core-gw-01"],
        )

        # Case A: Missing Infrastructure evidence (cannot claim absence of drops)
        outcome_unverified = arbiter.arbitrate([telemetry_high_latency], target_device="core-gw-01")
        assert outcome_unverified.status != "diagnosed"
        assert any("cannot be diagnosed without explicit infrastructure evidence" in lim for lim in outcome_unverified.limitations)

        # Case B: Explicit infrastructure evidence confirming zero drops and normal CPU
        infra_verified = AgentFinding(
            agent_name="InfrastructureAgent",
            status="healthy",
            hypothesis="Hardware nominal: zero drops and low CPU.",
            confidence=0.92,
            supporting_evidence=[
                MetricEvidence(
                    metric="egress_queue_drops",
                    value=0.0,
                    interpretation="Zero egress queue drops.",
                    canonical_key="queue_drops",
                ),
                MetricEvidence(
                    metric="cpu_utilization_pct",
                    value=22.0,
                    interpretation="CPU load is healthy at 22%.",
                    canonical_key="cpu",
                ),
            ],
            affected_devices=["core-gw-01"],
        )

        outcome_diagnosed = arbiter.arbitrate([telemetry_high_latency, infra_verified], target_device="core-gw-01")
        assert outcome_diagnosed.status == "diagnosed"
        assert "Upstream transit link delay or WAN propagation latency" in outcome_diagnosed.suspected_root_cause

    def test_tiny_crc_counter_treated_as_weak_evidence(self) -> None:
        """
        A CRC counter <= min_crc_threshold (default 5.0) must be treated as weak/incidental evidence
        and NOT trigger a physical layer degradation diagnosis.
        """
        arbiter = ArbiterAgent(min_crc_threshold=5.0)

        weak_crc_finding = AgentFinding(
            agent_name="InfrastructureAgent",
            status="anomaly_detected",
            hypothesis="Incidental bit flip observed.",
            confidence=0.70,
            supporting_evidence=[
                MetricEvidence(
                    metric="interface_crc_errors",
                    value=2.0,
                    interpretation="2 CRC frame errors observed.",
                    canonical_key="crc_errors",
                )
            ],
            affected_devices=["dist-rtr-01"],
        )
        telemetry_corroboration = AgentFinding(
            agent_name="TelemetryAgent",
            status="healthy",
            hypothesis="Transport metrics nominal.",
            confidence=0.90,
            supporting_evidence=[
                MetricEvidence(
                    metric="packet_loss_pct",
                    value=0.0,
                    interpretation="Zero loss.",
                    canonical_key="packet_loss",
                )
            ],
            affected_devices=["dist-rtr-01"],
        )

        outcome = arbiter.arbitrate([weak_crc_finding, telemetry_corroboration], target_device="dist-rtr-01")
        assert "Physical layer cable or transceiver degradation" not in outcome.suspected_root_cause
        assert any("below actionable threshold" in lim for lim in outcome.limitations)

        # Actionable CRC above threshold triggers diagnosis
        actionable_crc_finding = AgentFinding(
            agent_name="InfrastructureAgent",
            status="anomaly_detected",
            hypothesis="Physical layer cable degradation.",
            confidence=0.94,
            supporting_evidence=[
                MetricEvidence(
                    metric="interface_crc_errors",
                    value=42.0,
                    interpretation="42 CRC frame errors observed.",
                    canonical_key="crc_errors",
                )
            ],
            affected_devices=["dist-rtr-01"],
        )
        loss_corroboration = AgentFinding(
            agent_name="TelemetryAgent",
            status="anomaly_detected",
            hypothesis="Frame loss on interface.",
            confidence=0.88,
            supporting_evidence=[
                MetricEvidence(
                    metric="packet_loss_pct",
                    value=3.2,
                    interpretation="3.2% packet loss from frame errors.",
                    canonical_key="packet_loss",
                )
            ],
            affected_devices=["dist-rtr-01"],
        )

        outcome_actionable = arbiter.arbitrate([actionable_crc_finding, loss_corroboration], target_device="dist-rtr-01")
        assert outcome_actionable.status == "diagnosed"
        assert "Physical layer cable or transceiver degradation" in outcome_actionable.suspected_root_cause

    def test_interface_fault_errors_and_flapping_rule(self) -> None:
        """
        Validates interface fault rule (flapping + errors + transport loss).
        """
        arbiter = ArbiterAgent()

        infra_finding = AgentFinding(
            agent_name="InfrastructureAgent",
            status="anomaly_detected",
            hypothesis="Interface flapping and packet errors.",
            confidence=0.93,
            supporting_evidence=[
                MetricEvidence(
                    metric="link_flaps",
                    value=7.0,
                    interpretation="7 link state transitions in window.",
                    canonical_key="link_flaps",
                ),
                MetricEvidence(
                    metric="interface_errors",
                    value=55.0,
                    interpretation="55 interface input/output errors.",
                    canonical_key="interface_errors",
                ),
            ],
            affected_devices=["acc-sw-01"],
        )
        telemetry_finding = AgentFinding(
            agent_name="TelemetryAgent",
            status="anomaly_detected",
            hypothesis="Transport packet drops.",
            confidence=0.89,
            supporting_evidence=[
                MetricEvidence(
                    metric="packet_loss_pct",
                    value=5.0,
                    interpretation="5% packet loss.",
                    canonical_key="packet_loss",
                )
            ],
            affected_devices=["acc-sw-01"],
        )

        outcome = arbiter.arbitrate([infra_finding, telemetry_finding], target_device="acc-sw-01")
        assert outcome.status == "diagnosed"
        assert "Physical interface fault" in outcome.suspected_root_cause

    def test_link_down_precedence_over_telemetry(self) -> None:
        """
        Validates Layer 1/2 operational status down precedence.
        """
        arbiter = ArbiterAgent()

        infra_finding = AgentFinding(
            agent_name="InfrastructureAgent",
            status="anomaly_detected",
            hypothesis="Interface port operational status is DOWN.",
            confidence=0.96,
            supporting_evidence=[
                MetricEvidence(
                    metric="oper_status",
                    value=0.0,
                    interpretation="Port operational status is 0 (DOWN).",
                    canonical_key="oper_status",
                )
            ],
            affected_devices=["edge-ap-02"],
        )
        telemetry_finding = AgentFinding(
            agent_name="TelemetryAgent",
            status="anomaly_detected",
            hypothesis="100% loss due to unreachable port.",
            confidence=0.95,
            supporting_evidence=[
                MetricEvidence(
                    metric="packet_loss_pct",
                    value=100.0,
                    interpretation="100% packet loss.",
                    canonical_key="packet_loss",
                )
            ],
            affected_devices=["edge-ap-02"],
        )

        outcome = arbiter.arbitrate([infra_finding, telemetry_finding], target_device="edge-ap-02")
        assert outcome.status == "diagnosed"
        assert "Physical interface operational link-down failure" in outcome.suspected_root_cause

    def test_service_failure_with_healthy_transport(self) -> None:
        """
        Validates DNS/DHCP service failure diagnosis when transport layer is healthy.
        """
        arbiter = ArbiterAgent()

        service_finding = AgentFinding(
            agent_name="ServiceAgent",
            status="anomaly_detected",
            hypothesis="DNS resolution timeouts.",
            confidence=0.92,
            supporting_evidence=[
                MetricEvidence(
                    metric="dns_resolution_time_ms",
                    value=820.0,
                    interpretation="DNS lookup time is 820ms.",
                    canonical_key="dns_time",
                ),
                MetricEvidence(
                    metric="dns_failure_rate_pct",
                    value=14.0,
                    interpretation="DNS failure rate is 14%.",
                    canonical_key="dns_failure_rate",
                ),
            ],
            affected_devices=["HOSTEL_CORE_SW_01"],
        )
        telemetry_healthy = AgentFinding(
            agent_name="TelemetryAgent",
            status="healthy",
            hypothesis="Transport layer latency and loss nominal.",
            confidence=0.90,
            supporting_evidence=[
                MetricEvidence(
                    metric="rtt_latency_ms",
                    value=15.0,
                    interpretation="Latency is 15ms.",
                    canonical_key="latency",
                )
            ],
            affected_devices=["HOSTEL_CORE_SW_01"],
        )

        outcome = arbiter.arbitrate([service_finding, telemetry_healthy], target_device="HOSTEL_CORE_SW_01")
        assert outcome.status == "diagnosed"
        assert "Core network service failure" in outcome.suspected_root_cause

    def test_confidence_formula_mathematical_precision(self) -> None:
        """
        Validates confidence formula:
            Confidence = Weighted_Agent_Confidence * Corroboration_Factor * Data_Completeness
        """
        arbiter = ArbiterAgent()

        f1 = AgentFinding(
            agent_name="InfrastructureAgent",  # Weight 1.2
            status="anomaly_detected",
            hypothesis="Hardware drop.",
            confidence=0.90,
            supporting_evidence=[
                MetricEvidence(metric="egress_queue_drops", value=100.0, interpretation="drops", canonical_key="queue_drops")
            ],
        )
        f2 = AgentFinding(
            agent_name="TelemetryAgent",  # Weight 1.0
            status="anomaly_detected",
            hypothesis="Latency spike.",
            confidence=0.80,
            supporting_evidence=[
                MetricEvidence(metric="rtt_latency_ms", value=120.0, interpretation="latency", canonical_key="latency")
            ],
        )

        # Weighted conf = (0.90*1.2 + 0.80*1.0) / (1.2 + 1.0) = (1.08 + 0.80) / 2.2 = 1.88 / 2.2 = 0.8545
        # Corroboration factor for 2 agents = 1.00
        # Data completeness with 2 observed metrics out of 3 expected = 0.70 + 0.30 * (2/3) = 0.90
        # Expected = 0.8545 * 1.00 * 0.90 = 0.769 -> 0.77
        computed = arbiter._calculate_confidence([f1, f2], f1.supporting_evidence + f2.supporting_evidence, expected_metric_count=3)
        assert computed == 0.77

    def test_dynamic_alternative_causes_built_from_competing_hypotheses(self) -> None:
        """
        Validates that alternative causes are constructed dynamically from competing agent hypotheses
        instead of static canned lists.
        """
        arbiter = ArbiterAgent()

        infra_finding = AgentFinding(
            agent_name="InfrastructureAgent",
            status="anomaly_detected",
            hypothesis="Egress queue buffer overflow.",
            confidence=0.92,
            supporting_evidence=[
                MetricEvidence(metric="egress_queue_drops", value=200.0, interpretation="drops", canonical_key="queue_drops")
            ],
            affected_devices=["HOSTEL_CORE_SW_01"],
        )
        telemetry_finding = AgentFinding(
            agent_name="TelemetryAgent",
            status="anomaly_detected",
            hypothesis="Bandwidth saturation on link.",
            confidence=0.91,
            supporting_evidence=[
                MetricEvidence(metric="rtt_latency_ms", value=140.0, interpretation="high latency", canonical_key="latency")
            ],
            affected_devices=["HOSTEL_CORE_SW_01"],
        )
        topology_finding = AgentFinding(
            agent_name="TopologyAgent",
            status="anomaly_detected",
            hypothesis="Critical aggregation node blast radius expands across 6 switches.",
            confidence=0.88,
            supporting_evidence=[
                MetricEvidence(metric="downstream_blast_radius", value=6.0, interpretation="blast", canonical_key="downstream_blast_radius")
            ],
            affected_devices=["HOSTEL_CORE_SW_01"],
        )

        outcome = arbiter.arbitrate([infra_finding, telemetry_finding, topology_finding], target_device="HOSTEL_CORE_SW_01")
        assert outcome.status == "diagnosed"
        # Alternative causes must include the competing agent hypotheses with their agent name prefixes
        assert any("TopologyAgent: Critical aggregation node blast radius" in alt for alt in outcome.alternative_causes)

    def test_coordinator_end_to_end_upstream_device_fault_diagnosis(self) -> None:
        """
        Verify coordinator pipeline correctly identifies upstream device as root cause
        when target device shows symptoms and upstream device exhibits an active fault.
        """
        coordinator = NetCoopCoordinator()
        payload = {
            "scenario_id": "upstream_crc_propagation_test",
            "target_device": "edge-ap-01",
            "metrics": [
                {"metric_name": "rtt_latency_ms", "value": 150.0, "unit": "ms", "device_id": "edge-ap-01"},
                {"metric_name": "packet_loss_pct", "value": 3.8, "unit": "%", "device_id": "edge-ap-01"},
                {"metric_name": "interface_crc_errors", "value": 35.0, "unit": "count", "device_id": "acc-sw-01"},
            ],
        }
        report = coordinator.run(payload)
        assert isinstance(report, IncidentReport)
        assert report.status == "diagnosed"
        assert "acc-sw-01" in report.suspected_root_cause.lower()
        assert "edge-ap-01" in report.affected_devices
        assert "acc-sw-01" in report.affected_devices
        assert report.confidence >= 0.90


class TestReporterAgentRuleIdRecommendations:
    """
    Validates ReporterAgent recommendation mapping driven directly by rule_id on ArbitrationOutcome.
    """

    def test_microburst_queue_overflow_recommendations(self) -> None:
        reporter = ReporterAgent()
        outcome = ArbitrationOutcome(
            status="diagnosed",
            suspected_root_cause="Transient microburst forwarding queue overflow",
            confidence=0.92,
            affected_devices=["test-switch"],
            rule_id="microburst_overflow",
        )
        recs = reporter._determine_recommendations(outcome)
        assert len(recs) >= 3
        assert any("dynamic buffer sharing" in r.lower() or "burst" in r.lower() for r in recs)
        assert any("ecn" in r.lower() or "wred" in r.lower() for r in recs)

    def test_weak_wifi_rule_id_recommendations(self) -> None:
        reporter = ReporterAgent()
        outcome = ArbitrationOutcome(
            status="diagnosed",
            suspected_root_cause="Degraded wireless coverage",
            confidence=0.91,
            affected_devices=["edge-ap-01"],
            rule_id="weak_wifi",
        )
        recs = reporter._determine_recommendations(outcome)
        assert len(recs) >= 3
        assert any("rf spectrum" in r.lower() or "spectrum analysis" in r.lower() for r in recs)
        assert any("dfs" in r.lower() or "rrm" in r.lower() for r in recs)

    def test_link_down_rule_id_recommendations(self) -> None:
        reporter = ReporterAgent()
        outcome = ArbitrationOutcome(
            status="diagnosed",
            suspected_root_cause="Interface operational down",
            confidence=0.95,
            affected_devices=["edge-ap-02"],
            rule_id="link_down",
        )
        recs = reporter._determine_recommendations(outcome)
        assert len(recs) >= 3
        assert any("administrative status" in r.lower() or "no shutdown" in r.lower() for r in recs)

    def test_interface_fault_rule_id_recommendations(self) -> None:
        reporter = ReporterAgent()
        outcome = ArbitrationOutcome(
            status="diagnosed",
            suspected_root_cause="Interface packet corruption and flapping",
            confidence=0.93,
            affected_devices=["acc-sw-01"],
            rule_id="interface_fault",
        )
        recs = reporter._determine_recommendations(outcome)
        assert len(recs) >= 3
        assert any("auto-negotiation" in r.lower() or "transceiver" in r.lower() or "fiber" in r.lower() for r in recs)

    def test_service_failure_rule_id_recommendations(self) -> None:
        reporter = ReporterAgent()
        outcome = ArbitrationOutcome(
            status="diagnosed",
            suspected_root_cause="Application service failure",
            confidence=0.92,
            affected_devices=["HOSTEL_CORE_SW_01"],
            rule_id="service_failure",
        )
        recs = reporter._determine_recommendations(outcome)
        assert len(recs) >= 3
        assert any("dns" in r.lower() or "dhcp" in r.lower() for r in recs)
        assert any("ip helper-address" in r.lower() or "udp" in r.lower() for r in recs)

    def test_rule_id_takes_precedence_over_cause_text(self) -> None:
        reporter = ReporterAgent()
        # Even if cause string mentions "cable", rule_id="weak_wifi" drives Wi-Fi recommendations
        outcome = ArbitrationOutcome(
            status="diagnosed",
            suspected_root_cause="Ambiguous cable text",
            confidence=0.91,
            affected_devices=["ap-01"],
            rule_id="weak_wifi",
        )
        recs = reporter._determine_recommendations(outcome)
        assert any("rf spectrum" in r.lower() or "spectrum analysis" in r.lower() for r in recs)
