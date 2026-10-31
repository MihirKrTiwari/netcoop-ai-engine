"""
tests/test_agents.py
Comprehensive unit test suite for NetCoop AI domain-specific diagnostic agents.
"""

from typing import List
import pytest

from agents.base import BaseAgent
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
        assert any("Missing telemetry metrics" in lim for lim in finding.limitations)

    def test_telemetry_insufficient_evidence_when_latency_or_loss_jitter_missing(self) -> None:
        """
        Verify telemetry agent requires latency + at least one of (loss, jitter) to conclude healthy.
        """
        agent = TelemetryAgent()

        # Missing latency, only utilization and jitter
        payload_no_latency = RawTelemetryPayload(
            scenario_id="no_latency",
            target_device="edge-ap-01",
            metrics=[
                TelemetryMetric(metric_name="jitter_ms", value=2.0, unit="ms", device_id="edge-ap-01"),
                TelemetryMetric(metric_name="link_utilization_pct", value=30.0, unit="%", device_id="edge-ap-01"),
            ],
        )
        finding1 = agent.analyze(payload_no_latency)
        assert finding1.status == "insufficient_evidence"

        # Has latency, but neither loss nor jitter
        payload_no_loss_or_jitter = RawTelemetryPayload(
            scenario_id="no_loss_or_jitter",
            target_device="edge-ap-01",
            metrics=[
                TelemetryMetric(metric_name="rtt_latency_ms", value=15.0, unit="ms", device_id="edge-ap-01"),
                TelemetryMetric(metric_name="link_utilization_pct", value=30.0, unit="%", device_id="edge-ap-01"),
            ],
        )
        finding2 = agent.analyze(payload_no_loss_or_jitter)
        assert finding2.status == "insufficient_evidence"

    def test_telemetry_filters_by_device_id_and_timestamp(self) -> None:
        """
        Verify that foreign device readings and older samples are not mistakenly used.
        """
        metrics = [
            # High latency sample for target device at 14:30
            TelemetryMetric(
                metric_name="rtt_latency_ms",
                value=150.0,
                unit="ms",
                timestamp="2026-10-31T14:30:00Z",
                device_id="sw-target-01",
            ),
            # Low latency sample from a DIFFERENT device at 14:35
            TelemetryMetric(
                metric_name="rtt_latency_ms",
                value=10.0,
                unit="ms",
                timestamp="2026-10-31T14:35:00Z",
                device_id="sw-other-99",
            ),
            # Older low latency sample for target device at 14:15
            TelemetryMetric(
                metric_name="rtt_latency_ms",
                value=12.0,
                unit="ms",
                timestamp="2026-10-31T14:15:00Z",
                device_id="sw-target-01",
            ),
        ]
        payload = RawTelemetryPayload(
            scenario_id="timestamp_device_filter_test",
            target_device="sw-target-01",
            metrics=metrics,
        )

        agent = TelemetryAgent()
        finding = agent.analyze(payload)

        assert finding.status == "anomaly_detected"
        latency_ev = next(e for e in finding.supporting_evidence if "rtt" in e.metric.lower())
        assert latency_ev.value == 150.0


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

    def test_infrastructure_healthy_with_minimum_metrics(self) -> None:
        """
        Verify infrastructure agent can conclude healthy with at least one of (cpu, memory).
        """
        agent = InfrastructureAgent()

        # Only CPU provided
        payload_cpu_only = RawTelemetryPayload(
            scenario_id="cpu_only",
            target_device="edge-sw-01",
            metrics=[
                TelemetryMetric(metric_name="cpu_utilization_pct", value=35.0, unit="%", device_id="edge-sw-01"),
            ],
        )
        finding_cpu = agent.analyze(payload_cpu_only)
        assert finding_cpu.status == "healthy"
        assert any("Missing infrastructure metrics" in lim for lim in finding_cpu.limitations)

        # Neither CPU nor memory provided (only queue drops) -> insufficient_evidence
        payload_no_cpu_or_mem = RawTelemetryPayload(
            scenario_id="no_cpu_or_mem",
            target_device="edge-sw-01",
            metrics=[
                TelemetryMetric(metric_name="egress_queue_drops", value=0.0, unit="count", device_id="edge-sw-01"),
            ],
        )
        finding_drops = agent.analyze(payload_no_cpu_or_mem)
        assert finding_drops.status == "insufficient_evidence"

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

    def test_infrastructure_filters_device_id_and_newer_timestamp(self) -> None:
        metrics = [
            TelemetryMetric(
                metric_name="fcs_errors",
                value=180.0,
                unit="count",
                timestamp="2026-10-31T14:30:00Z",
                device_id="switch-core-01",
            ),
            TelemetryMetric(
                metric_name="fcs_errors",
                value=0.0,
                unit="count",
                timestamp="2026-10-31T14:35:00Z",
                device_id="switch-neighbor-02",
            ),
            TelemetryMetric(
                metric_name="fcs_errors",
                value=0.0,
                unit="count",
                timestamp="2026-10-31T14:10:00Z",
                device_id="switch-core-01",
            ),
        ]
        payload = RawTelemetryPayload(
            scenario_id="infra_filter_test",
            target_device="switch-core-01",
            metrics=metrics,
        )

        agent = InfrastructureAgent()
        finding = agent.analyze(payload)

        assert finding.status == "anomaly_detected"
        fcs_ev = next(e for e in finding.supporting_evidence if e.metric == "fcs_errors")
        assert fcs_ev.value == 180.0


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

    def test_redundancy_aware_core_gw_02_blast_radius(self) -> None:
        """
        core-gw-02 failure must NOT be classified as single-point-of-failure
        because all downstream devices maintain alternative paths via core-gw-01.
        """
        metrics = [
            TelemetryMetric(
                metric_name="link_state",
                value=0.0,
                unit="state",
                device_id="core-gw-02",
            )
        ]
        payload = RawTelemetryPayload(
            scenario_id="core_gw_redundancy_test",
            target_device="core-gw-02",
            metrics=metrics,
        )

        agent = TopologyAgent()
        finding = agent.analyze(payload)

        assert finding.status == "anomaly_detected"
        assert "single-point-of-failure" not in finding.hypothesis.lower()
        assert "redundancy" in finding.hypothesis.lower()

        radius_ev = next(e for e in finding.supporting_evidence if e.metric == "downstream_blast_radius")
        assert radius_ev.value == 0.0

    def test_topology_agent_healthy_device_status(self) -> None:
        """
        Ensure TopologyAgent returns status='healthy' when target device metrics are nominal.
        """
        metrics = [
            TelemetryMetric(
                metric_name="rtt_latency_ms",
                value=15.0,
                unit="ms",
                device_id="dist-rtr-01",
            ),
            TelemetryMetric(
                metric_name="packet_loss_pct",
                value=0.0,
                unit="%",
                device_id="dist-rtr-01",
            ),
        ]
        payload = RawTelemetryPayload(
            scenario_id="healthy_dist_rtr",
            target_device="dist-rtr-01",
            metrics=metrics,
        )

        agent = TopologyAgent()
        finding = agent.analyze(payload)

        assert finding.status == "healthy"
        assert "nominal" in finding.hypothesis.lower()

    def test_topology_agent_copies_topology_per_instance(self) -> None:
        """
        Verify that TopologyAgent copies the topology dict per instance
        and does not mutate CAMPUS_TOPOLOGY or other instances.
        """
        agent1 = TopologyAgent()
        agent1.topology["test-switch-isolated"] = {"upstream": [], "downstream": []}

        agent2 = TopologyAgent()
        assert "test-switch-isolated" not in agent2.topology

        from agents.topology_agent import CAMPUS_TOPOLOGY
        assert "test-switch-isolated" not in CAMPUS_TOPOLOGY

    def test_topology_agent_loads_custom_topology_from_payload_metadata(self) -> None:
        """
        Verify that TopologyAgent dynamically loads custom topology from payload.metadata.
        """
        payload = RawTelemetryPayload(
            scenario_id="meta_topo_test",
            target_device="sw-leaf-01",
            metadata={
                "topology": {
                    "sw-spine-01": {"upstream": [], "downstream": ["sw-leaf-01"]},
                    "sw-leaf-01": {"upstream": ["sw-spine-01"], "downstream": ["server-01"]},
                    "server-01": {"upstream": ["sw-leaf-01"], "downstream": []},
                }
            },
            metrics=[
                TelemetryMetric(metric_name="link_state", value=0.0, unit="state", device_id="sw-leaf-01"),
            ],
        )
        agent = TopologyAgent()
        finding = agent.analyze(payload)

        assert "server-01" in finding.affected_devices
        assert "sw-spine-01" in agent.get_upstream_dependencies("sw-leaf-01")

    def test_topology_agent_device_lookup_case_insensitive(self) -> None:
        """
        Verify case-insensitive device matching in topology lookups and blast radius.
        """
        agent = TopologyAgent()
        upstreams = agent.get_upstream_dependencies("EDGE-AP-01")
        assert any("acc-sw-01" == u.lower() for u in upstreams)

        blast = agent.compute_blast_radius("hostel_core_sw_01")
        assert len(blast) == 6
        assert any("hostel_acc_sw_01" == b.lower() for b in blast)

    def test_topology_agent_cycle_bug_start_node_never_in_blast_radius(self) -> None:
        """
        Verify that a cyclic topology does not enter an infinite loop
        and the start node NEVER appears in its own blast radius.
        """
        cyclic_topology = {
            "node-a": {"upstream": ["node-c"], "downstream": ["node-b"]},
            "node-b": {"upstream": ["node-a"], "downstream": ["node-c"]},
            "node-c": {"upstream": ["node-b"], "downstream": ["node-a"]},
        }
        agent = TopologyAgent(custom_topology=cyclic_topology)
        blast_a = agent.compute_blast_radius("node-a")
        assert "node-a" not in blast_a
        assert "NODE-A" not in [b.upper() for b in blast_a]

        isolated, redundant = agent.compute_redundancy_aware_blast_radius("node-a")
        assert "node-a" not in isolated
        assert "node-a" not in redundant

    def test_helper_get_metrics_by_device_case_insensitive(self) -> None:
        """
        Verify BaseAgent.get_metrics_by_device and payload.get_metrics_by_device
        group metrics with case-insensitive dict access.
        """
        metrics = [
            TelemetryMetric(metric_name="cpu_utilization_pct", value=92.0, unit="%", device_id="CORE-SW-01"),
            TelemetryMetric(metric_name="packet_loss_pct", value=4.5, unit="%", device_id="edge-ap-01"),
            TelemetryMetric(metric_name="rtt_latency_ms", value=120.0, unit="ms", device_id=""),
        ]
        payload = RawTelemetryPayload(
            scenario_id="multi_dev_test",
            target_device="edge-ap-01",
            metrics=metrics,
        )
        grouped = BaseAgent.get_metrics_by_device(payload)
        assert "core-sw-01" in grouped
        assert "CORE-SW-01" in grouped
        assert len(grouped["core-sw-01"]) == 1
        assert grouped["CORE-SW-01"][0].value == 92.0

        # Unassigned device_id defaults to target_device
        assert len(grouped["EDGE-AP-01"]) == 2
        assert payload.get_metrics_by_device()["core-sw-01"][0].value == 92.0

    def test_topology_agent_identifies_upstream_crc_fault_as_root_cause(self) -> None:
        """
        If target shows symptoms (high latency) and an upstream device shows a fault (CRC errors),
        report that upstream device as the probable root cause and list target as affected.
        """
        metrics = [
            TelemetryMetric(
                metric_name="rtt_latency_ms",
                value=140.0,
                unit="ms",
                device_id="edge-ap-01",
            ),
            TelemetryMetric(
                metric_name="interface_crc_errors",
                value=48.0,
                unit="count",
                device_id="acc-sw-01",
            ),
        ]
        payload = RawTelemetryPayload(
            scenario_id="upstream_crc_propagation",
            target_device="edge-ap-01",
            metrics=metrics,
        )

        agent = TopologyAgent()
        finding = agent.analyze(payload)

        assert finding.status == "anomaly_detected"
        assert "acc-sw-01" in finding.hypothesis
        assert "probable root cause" in finding.hypothesis.lower()
        assert "edge-ap-01" in finding.affected_devices
        assert "acc-sw-01" in finding.affected_devices
        assert any(e.canonical_key == "crc_errors" for e in finding.supporting_evidence)
        assert any(e.canonical_key == "latency" for e in finding.supporting_evidence)

    def test_topology_agent_identifies_upstream_high_cpu_fault_as_root_cause(self) -> None:
        """
        If target shows symptoms (packet loss) and an upstream device shows high CPU,
        report upstream device as probable root cause and list target as affected.
        """
        metrics = [
            TelemetryMetric(
                metric_name="packet_loss_pct",
                value=5.0,
                unit="%",
                device_id="edge-ap-01",
            ),
            TelemetryMetric(
                metric_name="cpu_utilization_pct",
                value=96.0,
                unit="%",
                device_id="dist-rtr-01",
            ),
        ]
        payload = RawTelemetryPayload(
            scenario_id="upstream_cpu_propagation",
            target_device="edge-ap-01",
            metrics=metrics,
        )

        agent = TopologyAgent()
        finding = agent.analyze(payload)

        assert finding.status == "anomaly_detected"
        assert "dist-rtr-01" in finding.hypothesis
        assert "edge-ap-01" in finding.affected_devices
        assert "dist-rtr-01" in finding.affected_devices


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

    def test_wireless_agent_insufficient_evidence_on_empty_metrics(
        self, empty_payload: RawTelemetryPayload
    ) -> None:
        from agents.wireless_agent import WirelessAgent
        agent = WirelessAgent()
        finding = agent.analyze(empty_payload)

        assert finding.agent_name == "WirelessAgent"
        assert finding.status == "insufficient_evidence"
        assert finding.confidence == 0.0
        assert len(finding.limitations) > 0

    def test_service_agent_insufficient_evidence_on_empty_metrics(
        self, empty_payload: RawTelemetryPayload
    ) -> None:
        from agents.service_agent import ServiceAgent
        agent = ServiceAgent()
        finding = agent.analyze(empty_payload)

        assert finding.agent_name == "ServiceAgent"
        assert finding.status == "insufficient_evidence"
        assert finding.confidence == 0.0
        assert len(finding.limitations) > 0


class TestWirelessAgent:
    """
    Unit test suite for WirelessAgent evaluating RSSI, SNR, and frame retransmission rates.
    """

    def test_detect_weak_rssi_and_low_snr(self) -> None:
        from agents.wireless_agent import WirelessAgent
        agent = WirelessAgent()

        payload = RawTelemetryPayload(
            scenario_id="wifi_attenuation_test",
            target_device="AP_HOSTEL_01",
            metrics=[
                TelemetryMetric(metric_name="rssi_dbm", value=-82.0, unit="dBm", device_id="AP_HOSTEL_01"),
                TelemetryMetric(metric_name="snr_db", value=9.5, unit="dB", device_id="AP_HOSTEL_01"),
                TelemetryMetric(metric_name="retransmission_rate_pct", value=18.5, unit="%", device_id="AP_HOSTEL_01"),
            ],
        )

        finding = agent.analyze(payload)

        assert finding.agent_name == "WirelessAgent"
        assert finding.status == "anomaly_detected"
        assert finding.confidence >= 0.88
        assert "weak RSSI" in finding.hypothesis
        assert "poor SNR" in finding.hypothesis
        assert "excessive retransmissions" in finding.hypothesis
        assert len(finding.supporting_evidence) == 3

        ev_map = {ev.metric: ev.value for ev in finding.supporting_evidence}
        assert ev_map["rssi_dbm"] == -82.0
        assert ev_map["snr_db"] == 9.5
        assert ev_map["retransmission_rate_pct"] == 18.5

    def test_healthy_wireless_parameters(self) -> None:
        from agents.wireless_agent import WirelessAgent
        agent = WirelessAgent()

        payload = RawTelemetryPayload(
            scenario_id="wifi_healthy_test",
            target_device="AP_HOSTEL_01",
            metrics=[
                TelemetryMetric(metric_name="rssi_dbm", value=-58.0, unit="dBm", device_id="AP_HOSTEL_01"),
                TelemetryMetric(metric_name="snr_db", value=32.0, unit="dB", device_id="AP_HOSTEL_01"),
                TelemetryMetric(metric_name="retransmission_rate_pct", value=1.8, unit="%", device_id="AP_HOSTEL_01"),
            ],
        )

        finding = agent.analyze(payload)

        assert finding.agent_name == "WirelessAgent"
        assert finding.status == "healthy"
        assert finding.confidence >= 0.90
        assert "nominal" in finding.hypothesis

    def test_wireless_unrecognized_units_recorded_as_limitations(self) -> None:
        from agents.wireless_agent import WirelessAgent
        agent = WirelessAgent()

        payload = RawTelemetryPayload(
            scenario_id="wifi_unit_test",
            target_device="AP_HOSTEL_01",
            metrics=[
                TelemetryMetric(metric_name="rssi_dbm", value=-80.0, unit="volts", device_id="AP_HOSTEL_01"),
            ],
        )

        finding = agent.analyze(payload)
        assert any("unit" in lim.lower() for lim in finding.limitations)


class TestServiceAgent:
    """
    Unit test suite for ServiceAgent evaluating DNS latency/failures and DHCP discover failures.
    """

    def test_detect_dns_latency_and_failure_rate(self) -> None:
        from agents.service_agent import ServiceAgent
        agent = ServiceAgent()

        payload = RawTelemetryPayload(
            scenario_id="dns_degradation_test",
            target_device="HOSTEL_CORE_SW_01",
            metrics=[
                TelemetryMetric(metric_name="dns_resolution_time_ms", value=680.0, unit="ms", device_id="HOSTEL_CORE_SW_01"),
                TelemetryMetric(metric_name="dns_failure_rate_pct", value=14.0, unit="%", device_id="HOSTEL_CORE_SW_01"),
            ],
        )

        finding = agent.analyze(payload)

        assert finding.agent_name == "ServiceAgent"
        assert finding.status == "anomaly_detected"
        assert finding.confidence >= 0.90
        assert "high_dns_resolution_time" in finding.hypothesis
        assert "high_dns_failure_rate" in finding.hypothesis

    def test_detect_dhcp_discover_failures(self) -> None:
        from agents.service_agent import ServiceAgent
        agent = ServiceAgent()

        payload = RawTelemetryPayload(
            scenario_id="dhcp_exhaustion_test",
            target_device="HOSTEL_CORE_SW_01",
            metrics=[
                TelemetryMetric(metric_name="dhcp_discover_failures", value=24.0, unit="count", device_id="HOSTEL_CORE_SW_01"),
            ],
        )

        finding = agent.analyze(payload)

        assert finding.agent_name == "ServiceAgent"
        assert finding.status == "anomaly_detected"
        assert "dhcp_discover_failures" in finding.hypothesis
        assert len(finding.supporting_evidence) == 1

    def test_healthy_service_metrics(self) -> None:
        from agents.service_agent import ServiceAgent
        agent = ServiceAgent()

        payload = RawTelemetryPayload(
            scenario_id="service_healthy_test",
            target_device="HOSTEL_CORE_SW_01",
            metrics=[
                TelemetryMetric(metric_name="dns_resolution_time_ms", value=18.0, unit="ms", device_id="HOSTEL_CORE_SW_01"),
                TelemetryMetric(metric_name="dns_failure_rate_pct", value=0.0, unit="%", device_id="HOSTEL_CORE_SW_01"),
                TelemetryMetric(metric_name="dhcp_discover_failures", value=0.0, unit="count", device_id="HOSTEL_CORE_SW_01"),
            ],
        )

        finding = agent.analyze(payload)

        assert finding.agent_name == "ServiceAgent"
        assert finding.status == "healthy"
        assert finding.confidence >= 0.90


class TestInfrastructureInterfaceHealth:
    """
    Unit test suite for InfrastructureAgent evaluating interface errors, link flaps,
    and operational/device status.
    """

    def test_detect_interface_link_down_and_flapping(self) -> None:
        agent = InfrastructureAgent()

        payload = RawTelemetryPayload(
            scenario_id="interface_down_test",
            target_device="DIST_SW_02",
            metrics=[
                TelemetryMetric(metric_name="cpu_utilization_pct", value=22.0, unit="%", device_id="DIST_SW_02"),
                TelemetryMetric(metric_name="link_flaps", value=9.0, unit="count", device_id="DIST_SW_02"),
                TelemetryMetric(metric_name="oper_status", value=0.0, unit="state", device_id="DIST_SW_02"),
            ],
        )

        finding = agent.analyze(payload)

        assert finding.agent_name == "InfrastructureAgent"
        assert finding.status == "anomaly_detected"
        assert finding.confidence >= 0.93
        assert "link-down" in finding.hypothesis.lower() or "flapping" in finding.hypothesis.lower()

    def test_detect_device_status_down(self) -> None:
        agent = InfrastructureAgent()

        payload = RawTelemetryPayload(
            scenario_id="device_down_test",
            target_device="DIST_SW_02",
            metrics=[
                TelemetryMetric(metric_name="device_status", value=0.0, unit="state", device_id="DIST_SW_02"),
            ],
        )

        finding = agent.analyze(payload)
        assert finding.status == "anomaly_detected"
        assert "device_status=0" in finding.hypothesis or "shutdown" in finding.hypothesis.lower()

    def test_detect_interface_packet_errors(self) -> None:
        agent = InfrastructureAgent()

        payload = RawTelemetryPayload(
            scenario_id="interface_errors_test",
            target_device="DIST_SW_02",
            metrics=[
                TelemetryMetric(metric_name="cpu_utilization_pct", value=15.0, unit="%", device_id="DIST_SW_02"),
                TelemetryMetric(metric_name="interface_errors", value=142.0, unit="count", device_id="DIST_SW_02"),
            ],
        )

        finding = agent.analyze(payload)
        assert finding.status == "anomaly_detected"
        assert "transceiver degradation" in finding.hypothesis.lower() or "errors" in finding.hypothesis.lower()


class TestTelemetryThroughputBandwidth:
    """
    Unit test suite for TelemetryAgent evaluating throughput and bandwidth starvation.
    """

    def test_detect_throughput_collapse_under_congestion(self) -> None:
        agent = TelemetryAgent()

        payload = RawTelemetryPayload(
            scenario_id="throughput_collapse_test",
            target_device="HOSTEL_CORE_SW_01",
            metrics=[
                TelemetryMetric(metric_name="rtt_latency_ms", value=160.0, unit="ms", device_id="HOSTEL_CORE_SW_01"),
                TelemetryMetric(metric_name="link_utilization_pct", value=98.0, unit="%", device_id="HOSTEL_CORE_SW_01"),
                TelemetryMetric(metric_name="throughput_mbps", value=0.25, unit="Mbps", device_id="HOSTEL_CORE_SW_01"),
            ],
        )

        finding = agent.analyze(payload)

        assert finding.agent_name == "TelemetryAgent"
        assert finding.status == "anomaly_detected"
        assert "throughput starvation" in finding.hypothesis.lower() or "bandwidth collapse" in finding.hypothesis.lower()
        assert any(ev.metric == "throughput_mbps" for ev in finding.supporting_evidence)

    def test_nominal_throughput_reported_in_evidence(self) -> None:
        agent = TelemetryAgent()

        payload = RawTelemetryPayload(
            scenario_id="nominal_throughput_test",
            target_device="HOSTEL_CORE_SW_01",
            metrics=[
                TelemetryMetric(metric_name="rtt_latency_ms", value=15.0, unit="ms", device_id="HOSTEL_CORE_SW_01"),
                TelemetryMetric(metric_name="packet_loss_pct", value=0.0, unit="%", device_id="HOSTEL_CORE_SW_01"),
                TelemetryMetric(metric_name="throughput_mbps", value=850.0, unit="Mbps", device_id="HOSTEL_CORE_SW_01"),
            ],
        )

        finding = agent.analyze(payload)
        assert finding.status == "healthy"
        assert any(ev.metric == "throughput_mbps" and ev.value == 850.0 for ev in finding.supporting_evidence)
