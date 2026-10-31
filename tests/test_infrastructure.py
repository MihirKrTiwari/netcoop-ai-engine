"""
tests/test_infrastructure.py
Unit tests for agents.infrastructure_agent.InfrastructureAgent (Member 3).

Verifies that the agent
  * flags egress buffer (queue) drops,
  * identifies physical-layer cable errors (CRC),
  * ignores normal hardware baselines,
and that it respects thresholds, units, device filtering, timestamps and missing data.

Run:  python -m pytest tests/test_infrastructure.py -v
"""
from agents.infrastructure_agent import InfrastructureAgent
from core.schemas import AgentFinding, RawTelemetryPayload, TelemetryMetric

DEVICE = "SW_EDGE_01"


def metric(name, value, unit="count", device=DEVICE, timestamp=None):
    return TelemetryMetric(metric_name=name, value=value, unit=unit, device_id=device, timestamp=timestamp)


def payload(*metrics, target=DEVICE, metadata=None):
    return RawTelemetryPayload(
        scenario_id="UNIT-INFRA", target_device=target, metrics=list(metrics), metadata=metadata or {}
    )


def healthy_set(**overrides):
    """A complete, normal hardware reading; overrides replace single metrics."""
    base = {
        "cpu_utilization_pct": (30.0, "%"),
        "memory_utilization_pct": (50.0, "%"),
        "egress_queue_drops": (0.0, "count"),
        "crc_errors": (0.0, "count"),
    }
    base.update(overrides)
    return [metric(n, v, u) for n, (v, u) in base.items()]


def run(*metrics, **kw):
    return InfrastructureAgent().analyze(payload(*metrics, **kw))


def keys(finding):
    return {e.canonical_key for e in finding.supporting_evidence}


# ---------------------------------------------------------------- normal baseline
def test_normal_hardware_baseline_is_healthy_and_not_flagged():
    f = run(*healthy_set())
    assert isinstance(f, AgentFinding)
    assert f.status == "healthy"
    assert f.confidence == 0.92
    assert "operating normally" in f.hypothesis
    assert f.affected_devices == [DEVICE]
    assert f.limitations == []
    assert keys(f) == {"cpu", "memory", "queue_drops", "crc_errors"}


def test_values_exactly_at_cpu_and_memory_thresholds_are_not_anomalies():
    f = run(*healthy_set(cpu_utilization_pct=(85.0, "%"), memory_utilization_pct=(90.0, "%")))
    assert f.status == "healthy"


def test_healthy_with_missing_optional_metrics_reports_limitation():
    f = run(metric("cpu", 20.0, "%"), metric("memory", 40.0, "%"))
    assert f.status == "healthy"
    assert any("Missing infrastructure metrics" in x and "queue_drops" in x and "crc_errors" in x
               for x in f.limitations)


# ---------------------------------------------------------------- buffer / queue drops
def test_egress_queue_drops_flag_buffer_overflow():
    f = run(*healthy_set(egress_queue_drops=(160.0, "count")))
    assert f.status == "anomaly_detected"
    assert "buffer overflow" in f.hypothesis.lower()
    assert f.confidence == 0.88
    drops = [e for e in f.supporting_evidence if e.canonical_key == "queue_drops"]
    assert drops and drops[0].value == 160.0
    assert "buffer overflow" in drops[0].interpretation


def test_single_queue_drop_is_still_flagged():
    f = run(*healthy_set(egress_queue_drops=(1.0, "count")))
    assert f.status == "anomaly_detected"


def test_queue_drops_with_high_cpu_is_resource_saturation_not_plain_buffer_overflow():
    f = run(*healthy_set(egress_queue_drops=(160.0, "count"), cpu_utilization_pct=(95.0, "%")))
    assert f.status == "anomaly_detected"
    assert "resource saturation" in f.hypothesis.lower()
    assert f.confidence == 0.90


# ---------------------------------------------------------------- cable / physical layer
def test_crc_errors_identify_cabling_or_transceiver_fault():
    f = run(*healthy_set(crc_errors=(250.0, "count")))
    assert f.status == "anomaly_detected"
    assert "cabling" in f.hypothesis.lower()
    assert f.confidence == 0.92
    crc = [e for e in f.supporting_evidence if e.canonical_key == "crc_errors"]
    assert crc and crc[0].value == 250.0


def test_a_single_crc_error_is_flagged():
    assert run(*healthy_set(crc_errors=(1.0, "count"))).status == "anomaly_detected"


def test_interface_packet_errors_are_treated_as_physical_degradation():
    f = run(*healthy_set(), metric("interface_errors", 40.0, "errors"))
    assert f.status == "anomaly_detected"
    assert "cabling" in f.hypothesis.lower()


def test_crc_plus_queue_drops_reported_together_with_highest_confidence():
    f = run(*healthy_set(crc_errors=(120.0, "count"), egress_queue_drops=(80.0, "count")))
    assert f.status == "anomaly_detected"
    assert "concurrent" in f.hypothesis.lower()
    assert f.confidence == 0.95


# ---------------------------------------------------------------- CPU / memory / status
def test_high_cpu_and_memory_is_control_plane_exhaustion():
    f = run(*healthy_set(cpu_utilization_pct=(96.0, "%"), memory_utilization_pct=(97.0, "%")))
    assert f.status == "anomaly_detected"
    assert "control plane resource exhaustion" in f.hypothesis.lower()
    assert f.confidence == 0.94


def test_high_cpu_alone_gets_moderate_confidence():
    f = run(*healthy_set(cpu_utilization_pct=(92.0, "%")))
    assert f.status == "anomaly_detected" and "cpu" in f.hypothesis.lower()
    assert f.confidence == 0.85


def test_high_memory_alone_is_memory_exhaustion():
    f = run(*healthy_set(memory_utilization_pct=(95.0, "%")))
    assert f.status == "anomaly_detected" and "memory exhaustion" in f.hypothesis.lower()


def test_device_status_down_is_most_severe_and_outranks_other_faults():
    f = run(*healthy_set(crc_errors=(500.0, "count")), metric("device_status", 0.0, "state"))
    assert f.status == "anomaly_detected"
    assert "node shutdown" in f.hypothesis.lower()
    assert f.confidence == 0.96


def test_link_down_detected_from_oper_status():
    f = run(*healthy_set(), metric("oper_status", 0.0, "state"))
    assert f.status == "anomaly_detected" and "link-down" in f.hypothesis.lower()
    assert f.confidence == 0.95


def test_link_up_and_device_up_are_not_anomalies():
    f = run(*healthy_set(), metric("oper_status", 1.0, "state"), metric("device_status", 1.0, "state"))
    assert f.status == "healthy"


def test_link_flaps_above_threshold_flagged_but_three_is_tolerated():
    assert run(*healthy_set(), metric("link_flaps", 5.0, "flaps")).status == "anomaly_detected"
    assert run(*healthy_set(), metric("link_flaps", 3.0, "flaps")).status == "healthy"


# ---------------------------------------------------------------- units & aliases
def test_ratio_units_are_converted_to_percent():
    f = run(*healthy_set(cpu_utilization_pct=(0.95, "ratio")))
    assert f.status == "anomaly_detected"
    cpu = [e for e in f.supporting_evidence if e.canonical_key == "cpu"][0]
    assert abs(cpu.value - 95.0) < 1e-9


def test_metric_name_aliases_are_recognized():
    f = run(metric("cpu_pct", 20.0, "%"), metric("ram_pct", 40.0, "%"),
            metric("tx_drops", 12.0, "drops"), metric("fcs_errors", 0.0, "errors"))
    assert keys(f) == {"cpu", "memory", "queue_drops", "crc_errors"}
    assert f.status == "anomaly_detected"  # tx_drops > 0


def test_unrecognized_unit_is_reported_as_limitation_not_trusted():
    f = run(metric("cpu", 99.0, "celsius"), metric("memory", 40.0, "%"))
    assert any("CPU unit 'celsius' unverified" in x for x in f.limitations)
    assert "cpu" not in keys(f)


# ---------------------------------------------------------------- device filtering / time
def test_other_devices_metrics_are_ignored():
    other = [metric("crc_errors", 900.0, "count", device="SW_OTHER_99")]
    f = run(*healthy_set(), *other)
    assert f.status == "healthy"


def test_newest_sample_wins_by_timestamp():
    old_bad = metric("cpu", 97.0, "%", timestamp="2026-10-31T10:00:00Z")
    new_ok = metric("cpu", 20.0, "%", timestamp="2026-10-31T10:05:00Z")
    f = run(old_bad, new_ok, metric("memory", 40.0, "%"))
    assert f.status == "healthy"
    f2 = run(new_ok, old_bad, metric("memory", 40.0, "%"))  # order must not matter
    assert f2.status == "healthy"


# ---------------------------------------------------------------- insufficient / robustness
def test_empty_metrics_is_insufficient_evidence_with_zero_confidence():
    f = run()
    assert f.status == "insufficient_evidence"
    assert f.confidence == 0.0
    assert f.affected_devices == [DEVICE]
    assert f.limitations == ["metrics list was empty in payload"]


def test_ingestion_notes_are_carried_into_limitations():
    f = run(metadata={"ingestion_notes": ["dropped malformed metric"]})
    assert f.limitations == ["dropped malformed metric"]


def test_only_unrelated_metrics_is_insufficient_evidence():
    f = run(metric("wifi_rssi_dbm", -80.0, "dbm"))
    assert f.status == "insufficient_evidence" and f.confidence == 0.0


def test_no_cpu_or_memory_means_cannot_confirm_healthy():
    f = run(metric("egress_queue_drops", 0.0, "count"), metric("crc_errors", 0.0, "count"))
    assert f.status == "insufficient_evidence"
    assert f.confidence == 0.45
    assert any("cpu" in x and "memory" in x for x in f.limitations)


def test_every_result_is_a_valid_finding_with_bounded_confidence():
    cases = [
        healthy_set(),
        healthy_set(crc_errors=(10.0, "count")),
        healthy_set(egress_queue_drops=(10.0, "count")),
        [],
        [metric("junk", 1.0, "x")],
    ]
    agent = InfrastructureAgent()
    for ms in cases:
        f = agent.analyze(payload(*ms))
        assert isinstance(f, AgentFinding)
        assert 0.0 <= f.confidence <= 1.0
        assert f.agent_name == agent.name
