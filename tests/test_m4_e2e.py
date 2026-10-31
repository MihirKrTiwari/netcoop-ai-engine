"""End-to-end tests for Member 4 scenarios through NetCoopCoordinator pipeline.

Validates that all scenarios/m4_*.json produce the expected diagnostic outcomes
when run through the complete multi-agent pipeline (validator -> domain agents ->
arbiter -> reporter) without stubs.
"""
from pathlib import Path
import pytest

from core.coordinator import NetCoopCoordinator
from core.schemas import IncidentReport

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "scenarios"


@pytest.fixture
def coordinator() -> NetCoopCoordinator:
    return NetCoopCoordinator()


def test_m4_a_healthy_e2e(coordinator: NetCoopCoordinator) -> None:
    scenario_file = SCENARIO_DIR / "m4_A_healthy.json"
    assert scenario_file.exists()

    report: IncidentReport = coordinator.run_from_file(str(scenario_file))

    assert isinstance(report, IncidentReport)
    assert report.status in {"diagnosed", "healthy"}
    assert "normal" in report.suspected_root_cause.lower()
    assert report.root_cause_category == "healthy"
    assert report.confidence >= 0.85
    assert len(report.alternative_causes) == 0
    assert len(report.recommended_actions) >= 1

    # Verify latency was NOT marked as missing
    for lim in report.limitations:
        assert "missing telemetry metrics: latency" not in lim.lower()
        assert "missing: latency" not in lim.lower()


def test_m4_b_congestion_e2e(coordinator: NetCoopCoordinator) -> None:
    scenario_file = SCENARIO_DIR / "m4_B_congestion.json"
    assert scenario_file.exists()

    report: IncidentReport = coordinator.run_from_file(str(scenario_file))

    assert isinstance(report, IncidentReport)
    assert report.status == "diagnosed"
    assert report.root_cause_category == "link_congestion"
    assert "congestion" in report.suspected_root_cause.lower() or "buffer exhaustion" in report.suspected_root_cause.lower()
    assert report.confidence >= 0.85

    # Evidence checks: 215 ms RTT and queue drops must be in supporting evidence
    metrics_present = {ev.metric: ev.value for ev in report.supporting_evidence}
    assert "rtt_latency_ms" in metrics_present
    assert metrics_present["rtt_latency_ms"] == pytest.approx(215.0)
    assert "egress_queue_drops" in metrics_present
    assert metrics_present["egress_queue_drops"] == pytest.approx(4820.0)

    # Must provide alternative causes and recommendations
    assert len(report.alternative_causes) >= 2
    assert len(report.recommended_actions) >= 2


def test_m4_c_link_flap_e2e(coordinator: NetCoopCoordinator) -> None:
    scenario_file = SCENARIO_DIR / "m4_C_link_flap.json"
    assert scenario_file.exists()

    report: IncidentReport = coordinator.run_from_file(str(scenario_file))

    assert isinstance(report, IncidentReport)
    assert report.status == "diagnosed"
    assert report.root_cause_category == "hardware_link_flap"
    assert any(term in report.suspected_root_cause.lower() for term in ["cable", "transceiver", "physical", "flap"])
    assert report.confidence >= 0.85
    assert len(report.supporting_evidence) >= 2
    assert len(report.recommended_actions) >= 2


def test_m4_d_dirty_data_e2e(coordinator: NetCoopCoordinator) -> None:
    scenario_file = SCENARIO_DIR / "m4_D_dirty_data.json"
    assert scenario_file.exists()

    report: IncidentReport = coordinator.run_from_file(str(scenario_file))

    assert isinstance(report, IncidentReport)
    assert report.status == "diagnosed"
    assert report.root_cause_category == "link_congestion"
    assert report.confidence >= 0.85

    # Dirty data must be reflected in limitations (dropped malformed metrics, conversions)
    assert len(report.limitations) > 0
    lim_text = " ".join(report.limitations).lower()
    assert "dropped" in lim_text or "coerced" in lim_text or "malformed" in lim_text


def test_m4_e_corrupt_e2e(coordinator: NetCoopCoordinator) -> None:
    scenario_file = SCENARIO_DIR / "m4_E_corrupt.json"
    assert scenario_file.exists()

    report: IncidentReport = coordinator.run_from_file(str(scenario_file))

    assert isinstance(report, IncidentReport)
    assert report.status == "insufficient_evidence"
    assert report.confidence <= 0.40
    assert len(report.limitations) > 0
    assert len(report.alternative_causes) == 0
