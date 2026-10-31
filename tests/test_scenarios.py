"""
tests/test_scenarios.py
Automated scenario execution test suite for NetCoop AI.
Validates all JSON scenario files through the CLI pipeline and asserts:
- Expected status (diagnosed, inconclusive, insufficient_evidence)
- Root cause keywords
- Calibrated confidence ranges
- Non-empty diagnostic limitations for degraded/interoperability inputs
- Explicit assertion that normal_ops.json is diagnosed as normal operation
- Explicit assertion that single-metric input is NEVER diagnosed
"""

import json
from pathlib import Path
import subprocess
import sys
from typing import Dict, List
import pytest

from core.coordinator import NetCoopCoordinator
from core.schemas import IncidentReport

SCENARIOS_DIR = Path("scenarios")


class TestScenarioExecution:
    """
    Validates end-to-end execution of every JSON scenario file.
    """

    @pytest.fixture
    def coordinator(self) -> NetCoopCoordinator:
        return NetCoopCoordinator()

    def test_normal_ops_diagnosed_as_normal_operation(self, coordinator: NetCoopCoordinator) -> None:
        """
        Explicit Requirement: normal_ops.json is diagnosed as normal operation.
        """
        scenario_file = SCENARIOS_DIR / "normal_ops.json"
        assert scenario_file.exists(), "normal_ops.json must exist"

        report = coordinator.run_from_file(str(scenario_file))
        assert isinstance(report, IncidentReport)
        assert report.status == "diagnosed"
        assert "normal" in report.suspected_root_cause.lower()
        assert report.confidence >= 0.85
        assert len(report.alternative_causes) == 0

    def test_single_metric_insufficient_is_never_diagnosed(self, coordinator: NetCoopCoordinator) -> None:
        """
        Explicit Requirement: Single-metric input is NEVER 'diagnosed'.
        Must degrade to inconclusive/insufficient_evidence with confidence capped <= 0.50.
        """
        scenario_file = SCENARIOS_DIR / "single_metric_insufficient.json"
        assert scenario_file.exists(), "single_metric_insufficient.json must exist"

        report = coordinator.run_from_file(str(scenario_file))
        assert isinstance(report, IncidentReport)
        # Strict Hackathon Rule: Never return diagnosed on a single metric
        assert report.status != "diagnosed"
        assert report.status in {"inconclusive", "insufficient_evidence"}
        assert report.confidence <= 0.50
        assert "inconclusive" in report.suspected_root_cause.lower() or "insufficient" in report.suspected_root_cause.lower()
        assert len(report.limitations) > 0

    def test_weak_wifi_scenario(self, coordinator: NetCoopCoordinator) -> None:
        scenario_file = SCENARIOS_DIR / "weak_wifi.json"
        assert scenario_file.exists()

        report = coordinator.run_from_file(str(scenario_file))
        assert report.status == "diagnosed"
        assert "wireless" in report.suspected_root_cause.lower() or "rf" in report.suspected_root_cause.lower()
        assert 0.85 <= report.confidence <= 1.0
        assert "WirelessAgent" in report.evidence_sources

    def test_interface_fault_scenario(self, coordinator: NetCoopCoordinator) -> None:
        scenario_file = SCENARIOS_DIR / "interface_fault.json"
        assert scenario_file.exists()

        report = coordinator.run_from_file(str(scenario_file))
        assert report.status == "diagnosed"
        assert "interface fault" in report.suspected_root_cause.lower() or "flapping" in report.suspected_root_cause.lower()
        assert 0.85 <= report.confidence <= 1.0

    def test_dns_dhcp_failure_scenario(self, coordinator: NetCoopCoordinator) -> None:
        scenario_file = SCENARIOS_DIR / "dns_dhcp_failure.json"
        assert scenario_file.exists()

        report = coordinator.run_from_file(str(scenario_file))
        assert report.status == "diagnosed"
        assert any(k in report.suspected_root_cause.lower() for k in ("dns", "dhcp", "service"))
        assert 0.85 <= report.confidence <= 1.0
        assert "ServiceAgent" in report.evidence_sources

    def test_interop_renamed_fields_scenario(self, coordinator: NetCoopCoordinator) -> None:
        scenario_file = SCENARIOS_DIR / "interop_renamed_fields.json"
        assert scenario_file.exists()

        report = coordinator.run_from_file(str(scenario_file))
        assert report.status == "diagnosed"
        assert 0.85 <= report.confidence <= 1.0
        # Assert non-empty limitations noting field adaptation
        assert len(report.limitations) > 0
        assert any("renamed field" in lim.lower() for lim in report.limitations)

    def test_interop_dict_metrics_scenario(self, coordinator: NetCoopCoordinator) -> None:
        scenario_file = SCENARIOS_DIR / "interop_dict_metrics.json"
        assert scenario_file.exists()

        report = coordinator.run_from_file(str(scenario_file))
        assert report.status == "diagnosed"
        assert 0.85 <= report.confidence <= 1.0
        # Assert non-empty limitations noting dict-to-list adaptation
        assert len(report.limitations) > 0
        assert any("dict" in lim.lower() for lim in report.limitations)

    def test_interop_unit_in_value_scenario(self, coordinator: NetCoopCoordinator) -> None:
        scenario_file = SCENARIOS_DIR / "interop_unit_in_value.json"
        assert scenario_file.exists()

        report = coordinator.run_from_file(str(scenario_file))
        assert report.status == "diagnosed"
        assert 0.85 <= report.confidence <= 1.0
        # Assert non-empty limitations noting unit extraction
        assert len(report.limitations) > 0
        assert any("unit" in lim.lower() for lim in report.limitations)

    def test_upstream_root_cause_scenario(self, coordinator: NetCoopCoordinator) -> None:
        scenario_file = SCENARIOS_DIR / "upstream_root_cause.json"
        assert scenario_file.exists()

        report = coordinator.run_from_file(str(scenario_file))
        assert report.status == "diagnosed"
        assert "acc-sw-01" in report.suspected_root_cause.lower() or "upstream device" in report.suspected_root_cause.lower()
        assert "acc-sw-01" in report.affected_devices
        assert "edge-ap-01" in report.affected_devices
        assert 0.85 <= report.confidence <= 1.0

    def test_link_down_scenario(self, coordinator: NetCoopCoordinator) -> None:
        scenario_file = SCENARIOS_DIR / "link_down.json"
        assert scenario_file.exists()

        report = coordinator.run_from_file(str(scenario_file))
        assert report.status == "diagnosed"
        assert "link-down" in report.suspected_root_cause.lower() or "link" in report.suspected_root_cause.lower()
        assert 0.85 <= report.confidence <= 1.0

    def test_malformed_data_degraded_scenario(self, coordinator: NetCoopCoordinator) -> None:
        scenario_file = SCENARIOS_DIR / "malformed_data.json"
        assert scenario_file.exists()

        report = coordinator.run_from_file(str(scenario_file))
        assert isinstance(report, IncidentReport)
        # Assert non-empty limitations for dropped invalid values and unit conversions
        assert len(report.limitations) > 0
        assert any("dropped" in lim.lower() or "conversion" in lim.lower() for lim in report.limitations)

    def test_link_congestion_scenario(self, coordinator: NetCoopCoordinator) -> None:
        scenario_file = SCENARIOS_DIR / "link_congestion.json"
        assert scenario_file.exists()

        report = coordinator.run_from_file(str(scenario_file))
        assert report.status == "diagnosed"
        assert "saturation" in report.suspected_root_cause.lower() or "queue" in report.suspected_root_cause.lower()
        assert 0.85 <= report.confidence <= 1.0


class TestCliPipelineOnAllScenarios:
    """
    Executes main.py via subprocess on each scenario file to verify standard CLI output.
    """

    @pytest.mark.parametrize(
        "scenario_filename",
        [
            "link_congestion.json",
            "normal_ops.json",
            "malformed_data.json",
            "weak_wifi.json",
            "interface_fault.json",
            "dns_dhcp_failure.json",
            "interop_renamed_fields.json",
            "interop_dict_metrics.json",
            "interop_unit_in_value.json",
            "upstream_root_cause.json",
            "link_down.json",
            "single_metric_insufficient.json",
        ],
    )
    def test_cli_execution_per_scenario(self, scenario_filename: str) -> None:
        scenario_path = SCENARIOS_DIR / scenario_filename
        assert scenario_path.exists()

        result = subprocess.run(
            [sys.executable, "main.py", "--scenario", str(scenario_path)],
            capture_output=True,
            text=True,
            check=True,
        )

        assert result.returncode == 0
        output_json = json.loads(result.stdout)
        assert "incident_id" in output_json
        assert "status" in output_json
        assert "suspected_root_cause" in output_json
        assert "confidence" in output_json
        assert "affected_devices" in output_json
        assert "recommended_actions" in output_json
