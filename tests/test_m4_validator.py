"""Member 4 tests: input sanitation + schema-valid reports.
Run from the repo root:  python -m pytest tests/test_m4_validator.py -v
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.incident_reporter import REQUIRED_FIELDS, ReporterAgent, validate_report  # noqa: E402
from core.validator import sanitize_payload  # noqa: E402

SCENARIO_DIR = ROOT / "scenarios"
SCENARIO_FILES = sorted(SCENARIO_DIR.glob("m4_*.json"))
reporter = ReporterAgent()


def clean_payload(**overrides):
    p = {"timestamp": "2026-10-31T09:00:00Z", "device_id": "sw-1",
         "metrics": {"throughput_mbps": 500, "rtt_ms": 10, "queue_drops": 0}}
    p["metrics"].update(overrides)
    return p


# ---------------- sanitation ----------------
def test_clean_payload_is_ok():
    r = sanitize_payload(clean_payload())
    assert r.status == "ok" and r.usable and not r.issues


def test_missing_timestamp_defaults():
    p = clean_payload()
    del p["timestamp"]
    r = sanitize_payload(p)
    assert r.usable and r.payload["timestamp"]
    assert any("timestamp" in i for i in r.issues)


def test_null_metric_dropped():
    r = sanitize_payload(clean_payload(queue_drops=None))
    assert "queue_drops" not in r.payload["metrics"]
    assert r.status == "degraded"


def test_strings_coerced_to_numbers():
    r = sanitize_payload(clean_payload(packet_loss_pct="4.2%", rtt_ms="12 ms"))
    assert r.payload["metrics"]["packet_loss_pct"] == pytest.approx(4.2)
    assert r.payload["metrics"]["rtt_ms"] == pytest.approx(12.0)


def test_unit_normalization_seconds_to_ms():
    p = clean_payload()
    del p["metrics"]["rtt_ms"]
    p["metrics"]["rtt_s"] = 0.25
    assert sanitize_payload(p).payload["metrics"]["rtt_ms"] == pytest.approx(250.0)


def test_gbps_to_mbps():
    p = clean_payload()
    del p["metrics"]["throughput_mbps"]
    p["metrics"]["throughput_gbps"] = 0.9
    assert sanitize_payload(p).payload["metrics"]["throughput_mbps"] == pytest.approx(900.0)


def test_out_of_range_dropped():
    r = sanitize_payload(clean_payload(link_utilization_pct=250))
    assert "link_utilization_pct" not in r.payload["metrics"]


def test_nan_and_inf_dropped():
    r = sanitize_payload(clean_payload(rtt_ms=float("nan"), queue_drops=float("inf")))
    assert "rtt_ms" not in r.payload["metrics"] and "queue_drops" not in r.payload["metrics"]


def test_json_string_input_accepted():
    assert sanitize_payload(json.dumps(clean_payload())).usable


@pytest.mark.parametrize("garbage", [None, "not json", "", [], 42, {}, b"\xff\xfe", {"metrics": "oops"}, [1, 2, 3]])
def test_garbage_never_raises(garbage):
    r = sanitize_payload(garbage)
    assert r.status == "insufficient_evidence" and not r.usable
    assert r.payload["metrics"] == {}


def test_all_metrics_null_is_insufficient():
    r = sanitize_payload({"metrics": {"rtt_ms": None, "queue_drops": "n/a", "crc_errors": ""}})
    assert r.status == "insufficient_evidence"


# ---------------- report schema (Section 6) ----------------
def make_verdict(**kw):
    v = {"root_cause": "link_congestion", "confidence": 0.87,
         "affected_devices": ["sw-1"],
         "contributing_agents": ["telemetry_agent", "topology_agent"],
         "evidence": ["queue_drops=4820", {"metric": "rtt_ms", "value": 215, "interpretation": "Elevated latency"}],
         "alternatives": [{"hypothesis": "hardware_fault", "confidence": 0.1, "reason": "CRC errors are zero"}]}
    v.update(kw)
    return v


def test_valid_report_passes_schema():
    rep = reporter.build_report(make_verdict(), sanitize_payload(clean_payload()))
    assert validate_report(rep) == []
    json.dumps(rep)


def test_section6_fields_present():
    rep = reporter.build_report(make_verdict(), sanitize_payload(clean_payload()))
    for k in ("incident_id", "status", "suspected_root_cause", "confidence", "affected_devices",
              "supporting_evidence", "alternative_causes", "recommended_actions",
              "evidence_sources", "limitations"):
        assert k in rep and k in REQUIRED_FIELDS
    assert rep["supporting_evidence"][0] == {"metric": "queue_drops", "value": 4820.0, "interpretation": ""}


@pytest.mark.parametrize("bad,expected", [(1.7, 1.0), (-3, 0.0), ("abc", 0.0), (None, 0.0), (float("nan"), 0.0), (0.42, 0.42)])
def test_confidence_is_bounded(bad, expected):
    rep = reporter.build_report(make_verdict(confidence=bad))
    assert 0.0 <= rep["confidence"] <= 1.0
    assert rep["confidence"] == pytest.approx(expected)
    assert validate_report(rep) == []


def test_corrupt_input_yields_insufficient_evidence_report():
    rep = reporter.build_report(make_verdict(), sanitize_payload("garbage"))
    assert rep["status"] == "insufficient_evidence" and rep["confidence"] == 0.0
    assert validate_report(rep) == []


@pytest.mark.parametrize("verdict", [None, {}, "text", [], {"root_cause": None}, {"root_cause": "alien_attack", "confidence": 0.5}])
def test_weird_verdicts_still_schema_valid(verdict):
    assert validate_report(reporter.build_report(verdict)) == []


def test_remediation_matches_root_cause():
    cong = reporter.build_report(make_verdict(root_cause="bufferbloat"))
    hw = reporter.build_report(make_verdict(root_cause="crc_errors_link_flap"))
    assert "queue" in cong["recommended_actions"][0].lower()
    assert "cable" in hw["recommended_actions"][0].lower()
    assert len(cong["recommended_actions"]) >= 2


def test_validate_report_catches_violations():
    rep = reporter.build_report(make_verdict())
    rep["confidence"] = 1.5
    rep["status"] = "bogus"
    rep["limitations"] = "not a list"
    assert len(validate_report(rep)) >= 3
    assert validate_report({}) and validate_report(None)


def test_markdown_ticket_contains_key_sections():
    md = reporter.to_markdown(reporter.build_report(make_verdict()))
    for heading in ("# Incident", "## Summary", "## Supporting evidence", "## Recommended actions"):
        assert heading in md


# ---------------- scenario files ----------------
def test_scenario_files_present():
    names = {p.name for p in SCENARIO_FILES}
    assert {"m4_A_healthy.json", "m4_B_congestion.json", "m4_C_link_flap.json",
            "m4_D_dirty_data.json", "m4_E_corrupt.json"} <= names


@pytest.mark.parametrize("path", SCENARIO_FILES, ids=lambda p: p.name)
def test_every_scenario_runs_through_pipeline(path):
    raw = json.loads(path.read_text(encoding="utf-8"))
    expected = raw["expected"]
    validation = sanitize_payload(raw)
    assert validation.status == expected["validation"]
    verdict = {"root_cause": expected["root_cause"], "confidence": 0.8, "contributing_agents": ["stub"]}
    rep = reporter.build_report(verdict, validation)
    assert validate_report(rep) == []
    assert rep["status"] == expected["status"]