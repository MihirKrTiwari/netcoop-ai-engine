"""Robustness, edge-case resilience, and fault-tolerance test suite.

Validates that NetCoop AI Engine gracefully handles:
- Unknown or future schema versions
- Malformed JSON strings and files
- Empty files (0 bytes)
- UTF-8 with Byte Order Mark (BOM)
- All-corrupt / completely unparseable payloads
- Individual agent exception isolation (pipeline never crashes)
- Out-of-order and mixed-timezone timestamps
"""
from pathlib import Path
import tempfile
import pytest

from core.coordinator import NetCoopCoordinator
from core.schemas import IncidentReport, RawTelemetryPayload


@pytest.fixture
def coordinator() -> NetCoopCoordinator:
    return NetCoopCoordinator()


def test_unknown_schema_version_graceful(coordinator: NetCoopCoordinator) -> None:
    payload = {
        "schema_version": "99.0",
        "scenario_id": "future_schema_test",
        "target_device": "sw-1",
        "metrics": [
            {"metric_name": "rtt_latency_ms", "value": 15.0, "unit": "ms"},
            {"metric_name": "cpu_utilization_pct", "value": 20.0, "unit": "%"}
        ]
    }
    report = coordinator.run(payload)
    assert isinstance(report, IncidentReport)
    # Limitation should record unsupported schema version
    assert any("schema_version" in lim.lower() for lim in report.limitations)


def test_malformed_json_file(coordinator: NetCoopCoordinator, tmp_path: Path) -> None:
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{ this is definitely not valid json : [", encoding="utf-8")

    report = coordinator.run_from_file(str(bad_json))
    assert isinstance(report, IncidentReport)
    assert report.status == "insufficient_evidence"
    assert report.confidence <= 0.40
    assert any("json" in lim.lower() or "malformed" in lim.lower() for lim in report.limitations)


def test_empty_file_handling(coordinator: NetCoopCoordinator, tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.json"
    empty_file.write_text("", encoding="utf-8")

    report = coordinator.run_from_file(str(empty_file))
    assert isinstance(report, IncidentReport)
    assert report.status == "insufficient_evidence"
    assert report.confidence == 0.0
    assert any("empty" in lim.lower() for lim in report.limitations)


def test_utf8_bom_file_handling(coordinator: NetCoopCoordinator, tmp_path: Path) -> None:
    bom_file = tmp_path / "bom.json"
    # UTF-8 BOM is \xef\xbb\xbf
    bom_content = '\ufeff{"target_device": "sw-1", "metrics": [{"metric_name": "rtt_ms", "value": 4.0}, {"metric_name": "queue_drops", "value": 0}]}'
    bom_file.write_text(bom_content, encoding="utf-8-sig")

    report = coordinator.run_from_file(str(bom_file))
    assert isinstance(report, IncidentReport)
    assert report.status in {"diagnosed", "healthy"}


def test_all_corrupt_payload_handling(coordinator: NetCoopCoordinator) -> None:
    corrupt_payload = {
        "metrics": {
            "throughput": None,
            "latency": "broken",
            "queue_drops": [1, 2, 3],
            "crc_errors": {}
        }
    }
    report = coordinator.run(corrupt_payload)
    assert isinstance(report, IncidentReport)
    assert report.status == "insufficient_evidence"
    assert report.confidence == 0.0
    assert len(report.limitations) > 0


def test_individual_agent_exception_isolation(coordinator: NetCoopCoordinator) -> None:
    class FailingAgent:
        name = "CrashAgent"
        def analyze(self, payload):
            raise RuntimeError("Simulated internal agent fault")

    original_agent = coordinator.service_agent
    coordinator.service_agent = FailingAgent()
    try:
        report = coordinator.run({
            "target_device": "core-sw-01",
            "metrics": [
                {"metric_name": "rtt_latency_ms", "value": 150.0, "unit": "ms"},
                {"metric_name": "egress_queue_drops", "value": 500.0, "unit": "count"},
                {"metric_name": "link_utilization_pct", "value": 90.0, "unit": "%"}
            ]
        })
        assert isinstance(report, IncidentReport)
        # The crash was caught, other agents still produced valid diagnosis
        assert report.status == "diagnosed"
        assert any("CrashAgent" in lim for lim in report.limitations)
    finally:
        coordinator.service_agent = original_agent
