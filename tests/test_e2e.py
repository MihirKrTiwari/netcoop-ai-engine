"""
tests/test_e2e.py
End-to-end integration tests for NetCoop AI multi-agent diagnosis pipeline and CLI.
"""

import json
import subprocess
import sys
from pathlib import Path
import pytest

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
    Test suite validating explicit Arbiter conflict resolution rules.
    """

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
