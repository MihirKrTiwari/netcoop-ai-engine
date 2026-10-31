"""
tests/test_agents.py
Comprehensive unit test suite for NetCoop AI domain-specific diagnostic agents.
"""

from typing import List
import pytest

from agents.infrastructure_agent import InfrastructureAgent
from agents.telemetry_agent import TelemetryAgent
from agents.topology_agent import TopologyAgent
from core.schemas import AgentFinding, RawTelemetryPayload, TelemetryMetric


@pytest.fixture
def empty_payload() -> RawTelemetryPayload:
    return RawTelemetryPayload(
        scenario_id="scenario_empty_01",
        target_device="edge-ap-01",
        metrics=[],
        metadata={},
    )


class TestTelemetryAgent:
    """
    Validation of TelemetryAgent heuristics, threshold detection, and evidence output.
    """

    def test_detect_link_congestion_under_high_latency_and_loss(self) -> None:
        metrics: List[TelemetryMetric] = [
            TelemetryMetric(
                metric_name="rtt_latency_ms",
                value=120.0,
                unit="ms",
                device_id="dist-rtr-01",
            ),
            TelemetryMetric(
                metric_name="packet_loss_pct",
                value=5.5,
                unit="%",
                device_id="dist-rtr-01",
            ),
            TelemetryMetric(
                metric_name="link_utilization_pct",
                value=96.0,
                unit="%",
                device_id="dist-rtr-01",
            ),
        ]
        payload = RawTelemetryPayload(
            scenario_id="congested_link_01",
            target_device="dist-rtr-01",
            metrics=metrics,
            metadata={"priority": "high"},
        )

        agent = TelemetryAgent()
        finding: AgentFinding = agent.analyze(payload)

        assert finding.agent_name == "TelemetryAgent"
        assert finding.status == "anomaly_detected"
        assert finding.confidence >= 0.90
        assert "saturation" in finding.hypothesis.lower() or "congestion" in finding.hypothesis.lower()
        assert "dist-rtr-01" in finding.affected_devices

        evidence_names = {e.metric for e in finding.supporting_evidence}
        assert "rtt_latency_ms" in evidence_names
        assert "packet_loss_pct" in evidence_names
        assert "link_utilization_pct" in evidence_names

    def test_healthy_telemetry_baseline(self) -> None:
        metrics: List[TelemetryMetric] = [
            TelemetryMetric(
                metric_name="rtt_latency_ms",
                value=18.0,
                unit="ms",
                device_id="edge-ap-01",
            ),
            TelemetryMetric(
                metric_name="packet_loss_pct",
                value=0.2,
                unit="%",
                device_id="edge-ap-01",
            ),
            TelemetryMetric(
                metric_name="jitter_ms",
                value=2.5,
                unit="ms",
                device_id="edge-ap-01",
            ),
        ]
        payload = RawTelemetryPayload(
            scenario_id="normal_ops_01",
            target_device="edge-ap-01",
            metrics=metrics,
        )

        agent = TelemetryAgent()
        finding = agent.analyze(payload)

        assert finding.status == "healthy"
        assert finding.confidence >= 0.85


class TestInfrastructureAgent:
    """
    Validation of InfrastructureAgent physical CRC errors, buffer drops, and CPU/RAM checks.
    """

    def test_detect_crc_errors_and_queue_drops(self) -> None:
        metrics: List[TelemetryMetric] = [
            TelemetryMetric(
                metric_name="interface_crc_errors",
                value=240.0,
                unit="count",
                device_id="acc-sw-01",
            ),
            TelemetryMetric(
                metric_name="egress_queue_drops",
                value=1850.0,
                unit="count",
                device_id="acc-sw-01",
            ),
            TelemetryMetric(
                metric_name="cpu_utilization_pct",
                value=42.0,
                unit="%",
                device_id="acc-sw-01",
            ),
        ]
        payload = RawTelemetryPayload(
            scenario_id="physical_degradation_01",
            target_device="acc-sw-01",
            metrics=metrics,
        )

        agent = InfrastructureAgent()
        finding: AgentFinding = agent.analyze(payload)

        assert finding.agent_name == "InfrastructureAgent"
        assert finding.status == "anomaly_detected"
        assert finding.confidence >= 0.90
        assert "physical" in finding.hypothesis.lower() or "crc" in finding.hypothesis.lower()
        assert "buffer" in finding.hypothesis.lower() or "queue" in finding.hypothesis.lower()
        assert "acc-sw-01" in finding.affected_devices

        evidence_names = {e.metric for e in finding.supporting_evidence}
        assert "interface_crc_errors" in evidence_names
        assert "egress_queue_drops" in evidence_names

    def test_detect_control_plane_exhaustion(self) -> None:
        metrics: List[TelemetryMetric] = [
            TelemetryMetric(
                metric_name="cpu_utilization_pct",
                value=94.5,
                unit="%",
                device_id="core-gw-01",
            ),
            TelemetryMetric(
                metric_name="memory_utilization_pct",
                value=96.0,
                unit="%",
                device_id="core-gw-01",
            ),
        ]
        payload = RawTelemetryPayload(
            scenario_id="control_plane_meltdown",
            target_device="core-gw-01",
            metrics=metrics,
        )

        agent = InfrastructureAgent()
        finding = agent.analyze(payload)

        assert finding.status == "anomaly_detected"
        assert "control plane" in finding.hypothesis.lower() or "cpu" in finding.hypothesis.lower()


class TestTopologyAgent:
    """
    Validation of TopologyAgent graph traversal, upstream pathing, and blast radius calculation.
    """

    def test_evaluate_upstream_blast_radius(self) -> None:
        metrics: List[TelemetryMetric] = [
            TelemetryMetric(
                metric_name="link_state",
                value=0.0,
                unit="state",
                device_id="dist-rtr-01",
            )
        ]
        payload = RawTelemetryPayload(
            scenario_id="upstream_failure_01",
            target_device="dist-rtr-01",
            metrics=metrics,
        )

        agent = TopologyAgent()
        finding: AgentFinding = agent.analyze(payload)

        assert finding.agent_name == "TopologyAgent"
        assert finding.status == "anomaly_detected"
        assert "single-point-of-failure" in finding.hypothesis.lower() or "upstream" in finding.hypothesis.lower()

        # dist-rtr-01 downstream dependents: acc-sw-01, acc-sw-02, edge-ap-01, edge-ap-02, edge-ap-03
        assert "acc-sw-01" in finding.affected_devices
        assert "acc-sw-02" in finding.affected_devices
        assert "edge-ap-01" in finding.affected_devices
        assert "edge-ap-02" in finding.affected_devices
        assert "edge-ap-03" in finding.affected_devices
        assert len(finding.affected_devices) == 6  # target + 5 dependents

        radius_evidence = next(e for e in finding.supporting_evidence if e.metric == "downstream_blast_radius")
        assert radius_evidence.value == 5.0

    def test_evaluate_edge_isolated_fault(self) -> None:
        metrics: List[TelemetryMetric] = [
            TelemetryMetric(
                metric_name="link_state",
                value=0.0,
                unit="state",
                device_id="edge-ap-01",
            )
        ]
        payload = RawTelemetryPayload(
            scenario_id="edge_failure_01",
            target_device="edge-ap-01",
            metrics=metrics,
        )

        agent = TopologyAgent()
        finding = agent.analyze(payload)

        assert finding.status == "anomaly_detected"
        assert "edge-isolated" in finding.hypothesis.lower()
        assert finding.affected_devices == ["edge-ap-01"]
        radius_evidence = next(e for e in finding.supporting_evidence if e.metric == "downstream_blast_radius")
        assert radius_evidence.value == 0.0


class TestInsufficientEvidenceHandling:
    """
    Ensure all domain agents safely return status="insufficient_evidence" when passed empty metrics.
    """

    def test_telemetry_agent_insufficient_evidence_on_empty_metrics(
        self, empty_payload: RawTelemetryPayload
    ) -> None:
        agent = TelemetryAgent()
        finding = agent.analyze(empty_payload)

        assert finding.agent_name == "TelemetryAgent"
        assert finding.status == "insufficient_evidence"
        assert finding.confidence == 0.0
        assert len(finding.limitations) > 0

    def test_infrastructure_agent_insufficient_evidence_on_empty_metrics(
        self, empty_payload: RawTelemetryPayload
    ) -> None:
        agent = InfrastructureAgent()
        finding = agent.analyze(empty_payload)

        assert finding.agent_name == "InfrastructureAgent"
        assert finding.status == "insufficient_evidence"
        assert finding.confidence == 0.0
        assert len(finding.limitations) > 0

    def test_topology_agent_insufficient_evidence_on_empty_metrics(
        self, empty_payload: RawTelemetryPayload
    ) -> None:
        agent = TopologyAgent()
        finding = agent.analyze(empty_payload)

        assert finding.agent_name == "TopologyAgent"
        assert finding.status == "insufficient_evidence"
        assert finding.confidence == 0.0
        assert len(finding.limitations) > 0
