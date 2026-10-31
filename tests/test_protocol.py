"""Unit and integration tests for the NetCoop Inter-Agent Protocol (core/protocol.py).

Validates:
1. AgentMessage envelope structure and Pydantic validation.
2. Schema version negotiation and compatibility checks.
3. MessageLog append, ordering, sequence numbering, and filtering.
4. JSONL export and import round-trip.
5. Coordinator integration: message log recording across all pipeline stages
   (telemetry ingest, agent findings, peer reviews, arbiter arbitration).
"""
import json
from pathlib import Path
import tempfile
import pytest

from core.protocol import (
    AgentMessage,
    MessageLog,
    check_schema_compatibility,
    export_message_log,
    load_message_log,
    SUPPORTED_SCHEMA_VERSIONS,
)
from core.coordinator import NetCoopCoordinator
from core.schemas import AgentFinding, MetricEvidence


def test_agent_message_envelope_creation() -> None:
    msg = AgentMessage(
        sender="TelemetryAgent",
        recipient="ArbiterAgent",
        message_type="finding",
        payload={"status": "anomaly_detected", "metric": "rtt_latency_ms"},
        correlation_id="inc-test-001",
        schema_version="1.0",
    )

    assert msg.message_id.startswith("msg-")
    assert msg.sender == "TelemetryAgent"
    assert msg.recipient == "ArbiterAgent"
    assert msg.message_type == "finding"
    assert msg.correlation_id == "inc-test-001"
    assert msg.schema_version == "1.0"
    assert msg.timestamp is not None
    assert msg.payload["metric"] == "rtt_latency_ms"


def test_schema_version_compatibility() -> None:
    # Supported versions
    for ver in SUPPORTED_SCHEMA_VERSIONS:
        compat, warning = check_schema_compatibility(ver)
        assert compat is True

    # Same major, higher minor -> compatible with note
    compat, note = check_schema_compatibility("1.9")
    assert compat is True
    assert note is not None
    assert "higher minor" in note.lower()

    # Incompatible major
    compat, note = check_schema_compatibility("2.0")
    assert compat is False
    assert "incompatible major" in note.lower()

    compat, note = check_schema_compatibility("0.9")
    assert compat is False

    # Empty / none
    compat, note = check_schema_compatibility(None)
    assert compat is True


def test_message_log_sequence_and_filtering() -> None:
    log = MessageLog(incident_id="inc-001")

    m1 = log.add(
        sender="Coordinator",
        recipient="TelemetryAgent",
        message_type="telemetry_ingest",
        payload={"device_id": "sw-1"},
    )
    m2 = log.add(
        sender="TelemetryAgent",
        recipient="ArbiterAgent",
        message_type="finding",
        payload={"status": "anomaly_detected"},
    )
    m3 = log.add(
        sender="InfrastructureAgent",
        recipient="TelemetryAgent",
        message_type="peer_review",
        payload={"corroborates": True},
    )

    assert len(log.messages) == 3
    assert m1.sequence_number == 1
    assert m2.sequence_number == 2
    assert m3.sequence_number == 3

    # Filter by recipient
    to_arbiter = log.get_messages(recipient="ArbiterAgent")
    assert len(to_arbiter) == 1
    assert to_arbiter[0].sender == "TelemetryAgent"

    # Filter by message_type
    peer_reviews = log.get_messages(message_type="peer_review")
    assert len(peer_reviews) == 1
    assert peer_reviews[0].sender == "InfrastructureAgent"


def test_message_log_jsonl_export_and_import() -> None:
    log = MessageLog(incident_id="inc-roundtrip")
    log.add(sender="A", recipient="B", message_type="test", payload={"key": "val1"})
    log.add(sender="B", recipient="C", message_type="test", payload={"key": "val2"})

    with tempfile.TemporaryDirectory() as tmpdir:
        jsonl_path = Path(tmpdir) / "test_messages.jsonl"
        export_message_log(log, jsonl_path)
        assert jsonl_path.exists()

        # Check line count and validity
        lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        for line in lines:
            data = json.loads(line)
            assert "message_id" in data
            assert "sender" in data
            assert "schema_version" in data

        # Reload
        reloaded = load_message_log(jsonl_path)
        assert len(reloaded) == 2
        assert reloaded[0].sender == "A"
        assert reloaded[1].recipient == "C"


def test_coordinator_generates_complete_message_log(tmp_path: Path) -> None:
    coordinator = NetCoopCoordinator()
    scenario_path = Path("scenarios/link_congestion.json")
    assert scenario_path.exists()

    report = coordinator.run_from_file(str(scenario_path))
    assert report.status == "diagnosed"

    log = coordinator.get_message_log()
    assert log is not None
    assert len(log.messages) > 0

    # Verify message sequence order
    seqs = [m.sequence_number for m in log.messages]
    assert seqs == list(range(1, len(log.messages) + 1))

    # Verify message types emitted during execution
    msg_types = {m.message_type for m in log.messages}
    assert "telemetry_ingest" in msg_types
    assert "agent_finding" in msg_types
    assert "peer_review" in msg_types
    assert "arbiter_verdict" in msg_types

    # Export to file
    out_file = tmp_path / "coordinator_log.jsonl"
    coordinator.export_message_log(str(out_file))
    assert out_file.exists()

    loaded = load_message_log(out_file)
    assert len(loaded) == len(log.messages)
