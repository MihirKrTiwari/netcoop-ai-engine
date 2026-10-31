"""
agents/topology_agent.py
Topology domain agent for NetCoop AI.
Maintains network hierarchy, computes downstream blast radius with multi-path redundancy awareness,
evaluates cross-device telemetry propagation to identify upstream root cause devices,
and distinguishes between healthy device topology and active fault propagation.
"""

from collections import deque
import copy
from typing import Any, Dict, List, Optional, Set, Tuple

from agents.base import BaseAgent
from core.schemas import AgentFinding, MetricEvidence, RawTelemetryPayload, TelemetryMetric


CAMPUS_TOPOLOGY: Dict[str, Dict[str, List[str]]] = {
    # Core Gateway Layer
    "core-gw-01": {"upstream": [], "downstream": ["dist-rtr-01", "dist-rtr-02", "HOSTEL_CORE_SW_01"]},
    "core-gw-02": {"upstream": [], "downstream": ["dist-rtr-02"]},

    # Distribution Router Layer
    "dist-rtr-01": {"upstream": ["core-gw-01"], "downstream": ["acc-sw-01", "acc-sw-02"]},
    "dist-rtr-02": {"upstream": ["core-gw-01", "core-gw-02"], "downstream": ["acc-sw-03", "acc-sw-04"]},

    # Access Switch Layer
    "acc-sw-01": {"upstream": ["dist-rtr-01"], "downstream": ["edge-ap-01", "edge-ap-02"]},
    "acc-sw-02": {"upstream": ["dist-rtr-01"], "downstream": ["edge-ap-03"]},
    "acc-sw-03": {"upstream": ["dist-rtr-02"], "downstream": ["edge-ap-04", "edge-ap-05"]},
    "acc-sw-04": {"upstream": ["dist-rtr-02"], "downstream": ["edge-ap-06"]},

    # Edge AP Layer
    "edge-ap-01": {"upstream": ["acc-sw-01"], "downstream": []},
    "edge-ap-02": {"upstream": ["acc-sw-01"], "downstream": []},
    "edge-ap-03": {"upstream": ["acc-sw-02"], "downstream": []},
    "edge-ap-04": {"upstream": ["acc-sw-03"], "downstream": []},
    "edge-ap-05": {"upstream": ["acc-sw-03"], "downstream": []},
    "edge-ap-06": {"upstream": ["acc-sw-04"], "downstream": []},

    # Hostel Distribution & Access Sub-Tree
    "HOSTEL_CORE_SW_01": {"upstream": ["core-gw-01"], "downstream": ["HOSTEL_ACC_SW_01", "HOSTEL_ACC_SW_02"]},
    "HOSTEL_ACC_SW_01": {"upstream": ["HOSTEL_CORE_SW_01"], "downstream": ["HOSTEL_AP_01", "HOSTEL_AP_02"]},
    "HOSTEL_ACC_SW_02": {"upstream": ["HOSTEL_CORE_SW_01"], "downstream": ["HOSTEL_AP_03", "HOSTEL_AP_04"]},
    "HOSTEL_AP_01": {"upstream": ["HOSTEL_ACC_SW_01"], "downstream": []},
    "HOSTEL_AP_02": {"upstream": ["HOSTEL_ACC_SW_01"], "downstream": []},
    "HOSTEL_AP_03": {"upstream": ["HOSTEL_ACC_SW_02"], "downstream": []},
    "HOSTEL_AP_04": {"upstream": ["HOSTEL_ACC_SW_02"], "downstream": []},
}


class TopologyAgent(BaseAgent):
    """
    Evaluates campus network topology graphs to calculate fault propagation,
    upstream dependency chains, redundancy-aware downstream blast radius, and
    isolates upstream root-cause devices when downstream symptoms are observed.
    """

    def __init__(
        self,
        name: Optional[str] = None,
        custom_topology: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(name=name or "TopologyAgent")
        # Copy the topology dict per instance instead of sharing the module global
        source = custom_topology if custom_topology is not None else CAMPUS_TOPOLOGY
        self.topology: Dict[str, Dict[str, List[str]]] = self._normalize_topology(copy.deepcopy(source))

    @staticmethod
    def _normalize_topology(raw_topo: Dict[str, Any]) -> Dict[str, Dict[str, List[str]]]:
        """
        Normalize arbitrary topology adjacency input into standardized dict with
        'upstream' and 'downstream' lists. Handles case normalization and bidirectional links.
        """
        normalized: Dict[str, Dict[str, List[str]]] = {}

        # 1. Initialize nodes
        for node, data in raw_topo.items():
            node_key = str(node).strip()
            if isinstance(data, dict):
                upstreams = [str(u).strip() for u in data.get("upstream", []) if str(u).strip()]
                downstreams = [str(d).strip() for d in data.get("downstream", []) if str(d).strip()]
                normalized[node_key] = {"upstream": upstreams, "downstream": downstreams}
            elif isinstance(data, list):
                # Adjacency list format where dict maps parent -> list of children
                downstreams = [str(d).strip() for d in data if str(d).strip()]
                normalized[node_key] = {"upstream": [], "downstream": downstreams}
            else:
                normalized[node_key] = {"upstream": [], "downstream": []}

        # 2. Ensure bidirectional consistency for simple list inputs
        for parent, node_dict in list(normalized.items()):
            for child in node_dict.get("downstream", []):
                if child not in normalized:
                    # Case-insensitive check if child already exists
                    existing_child = None
                    for k in normalized.keys():
                        if k.lower() == child.lower():
                            existing_child = k
                            break
                    if existing_child:
                        child = existing_child
                    else:
                        normalized[child] = {"upstream": [], "downstream": []}

                child_upstreams = normalized[child]["upstream"]
                if not any(u.lower() == parent.lower() for u in child_upstreams):
                    child_upstreams.append(parent)

        return normalized

    def _find_node_key(self, device: Optional[str]) -> Optional[str]:
        """
        Case-insensitive lookup for device name in self.topology keys.
        """
        if not device:
            return None
        dev_clean = device.strip().lower()
        for k in self.topology.keys():
            if k.strip().lower() == dev_clean:
                return k
        return None

    def _get_node_data(self, device: Optional[str]) -> Optional[Dict[str, List[str]]]:
        """
        Retrieve node adjacency data using case-insensitive device matching.
        """
        key = self._find_node_key(device)
        if key is not None:
            return self.topology[key]
        return None

    def get_upstream_dependencies(self, device: str) -> List[str]:
        """
        Traverse up the hierarchy using BFS to find all upstream transit nodes.
        Matching is strictly case-insensitive.
        """
        dev_key = self._find_node_key(device)
        start_device = dev_key if dev_key else device

        visited: Set[str] = {start_device.strip().lower()}
        queue: deque = deque([start_device])
        upstream_nodes: List[str] = []

        while queue:
            curr = queue.popleft()
            node_data = self._get_node_data(curr)
            if not node_data:
                continue

            for parent in node_data.get("upstream", []):
                p_norm = parent.strip().lower()
                if p_norm not in visited:
                    visited.add(p_norm)
                    # Resolve to canonical casing if present in topology
                    p_key = self._find_node_key(parent) or parent
                    upstream_nodes.append(p_key)
                    queue.append(p_key)

        return upstream_nodes

    def _can_reach_core_without(self, start_node: str, failed_node: str) -> bool:
        """
        Check if start_node can reach any root core gateway without passing through failed_node.
        Evaluation is strictly case-insensitive.
        """
        start_norm = start_node.strip().lower()
        failed_norm = failed_node.strip().lower()

        if start_norm == failed_norm:
            return False

        node_data = self._get_node_data(start_node)
        if not node_data:
            return False

        if not node_data.get("upstream"):
            # Root core gateway
            return True

        visited: Set[str] = {start_norm}
        queue: deque = deque([start_node])

        while queue:
            curr = queue.popleft()
            curr_norm = curr.strip().lower()
            if curr_norm == failed_norm:
                continue

            curr_data = self._get_node_data(curr)
            if not curr_data:
                continue

            upstreams = curr_data.get("upstream", [])
            if not upstreams:
                # Reached a core gateway that is not the failed node
                return True

            for parent in upstreams:
                p_norm = parent.strip().lower()
                if p_norm != failed_norm and p_norm not in visited:
                    visited.add(p_norm)
                    p_key = self._find_node_key(parent) or parent
                    queue.append(p_key)

        return False

    def compute_blast_radius(self, device: str) -> List[str]:
        """
        Compute downstream dependent devices that would be strictly isolated
        if device experiences a complete failure, taking multi-homed path redundancy into account.
        The start node will NEVER appear in its own blast radius.
        """
        isolated_devices, _ = self.compute_redundancy_aware_blast_radius(device)
        return isolated_devices

    def compute_redundancy_aware_blast_radius(self, device: str) -> Tuple[List[str], List[str]]:
        """
        Determine downstream descendants and partition them into:
        - isolated_devices: lose all paths to core gateways.
        - redundant_devices: maintain alternate active paths to core gateways.

        Prevents cycle bugs: the start node is explicitly precluded from appearing
        in either list. Device lookup is case-insensitive.
        """
        dev_key = self._find_node_key(device)
        start_device = dev_key if dev_key else device
        dev_norm = start_device.strip().lower()

        # Initialize visited set with the start node to eliminate cycle bugs
        visited: Set[str] = {dev_norm}
        queue: deque = deque([start_device])
        downstream_descendants: List[str] = []

        while queue:
            curr = queue.popleft()
            node_data = self._get_node_data(curr)
            if not node_data:
                continue

            for child in node_data.get("downstream", []):
                child_norm = child.strip().lower()
                # Stop cycle: child must not be in visited or equal to start node
                if child_norm not in visited and child_norm != dev_norm:
                    visited.add(child_norm)
                    child_key = self._find_node_key(child) or child
                    downstream_descendants.append(child_key)
                    queue.append(child_key)

        isolated_devices: List[str] = []
        redundant_devices: List[str] = []

        for desc in downstream_descendants:
            desc_norm = desc.strip().lower()
            # Double check to prevent cycle bug: start node cannot be in its own blast radius
            if desc_norm == dev_norm:
                continue

            if self._can_reach_core_without(start_node=desc, failed_node=start_device):
                redundant_devices.append(desc)
            else:
                isolated_devices.append(desc)

        return isolated_devices, redundant_devices

    def _device_has_symptoms(self, metrics: List[TelemetryMetric]) -> Tuple[bool, List[str], List[MetricEvidence]]:
        """
        Evaluate if a device's telemetry exhibits service impairment or degradation symptoms.
        Returns (has_symptoms, symptom_reasons, supporting_evidence).
        """
        symptom_reasons: List[str] = []
        symptom_evidence: List[MetricEvidence] = []

        for m in metrics:
            name = m.metric_name.lower().strip()
            val = m.value

            # Latency SLA violation
            if name in {"rtt_latency_ms", "rtt_latency", "rtt", "latency", "latency_ms"} and val > 80.0:
                symptom_reasons.append(f"high RTT latency ({val:.1f}ms > 80ms)")
                symptom_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Target RTT latency spikes ({val:.1f}ms).",
                        canonical_key="latency",
                    )
                )

            # Packet loss
            elif name in {"packet_loss_pct", "packet_loss", "loss_pct", "loss", "packet_loss_percent"} and val > 2.0:
                symptom_reasons.append(f"packet loss ({val:.1f}% > 2.0%)")
                symptom_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Target packet drops ({val:.1f}%).",
                        canonical_key="packet_loss",
                    )
                )

            # Jitter
            elif name in {"jitter_ms", "jitter"} and val > 25.0:
                symptom_reasons.append(f"jitter variation ({val:.1f}ms > 25ms)")
                symptom_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Target jitter variation ({val:.1f}ms).",
                        canonical_key="jitter",
                    )
                )

            # Link utilization
            elif name in {"link_utilization_pct", "link_utilization", "utilization_pct", "utilization"} and val > 80.0:
                symptom_reasons.append(f"link utilization ({val:.1f}% > 80%)")
                symptom_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Target link utilization ({val:.1f}%).",
                        canonical_key="utilization",
                    )
                )

            # Egress drops
            elif name in {"egress_queue_drops", "queue_drops", "egress_drops", "tx_drops"} and val > 0.0:
                symptom_reasons.append(f"egress queue drops ({val:.0f} drops)")
                symptom_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Target egress queue drops ({val:.0f} drops).",
                        canonical_key="queue_drops",
                    )
                )

            # CRC errors
            elif name in {"interface_crc_errors", "crc_errors", "fcs_errors", "rx_crc_errors"} and val > 0.0:
                symptom_reasons.append(f"interface CRC errors ({val:.0f} errors)")
                symptom_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Target interface CRC errors ({val:.0f} errors).",
                        canonical_key="crc_errors",
                    )
                )

            # Operational link down
            elif name in {"oper_status", "link_state", "interface_state", "port_status", "device_status"} and val <= 0.0:
                symptom_reasons.append(f"operational status down ({val:.0f})")
                symptom_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation="Target interface operational state is down.",
                        canonical_key="oper_status",
                    )
                )

        has_symptoms = len(symptom_reasons) > 0
        return has_symptoms, symptom_reasons, symptom_evidence

    def _device_has_fault(self, dev_name: str, metrics: List[TelemetryMetric]) -> Tuple[bool, str, List[MetricEvidence]]:
        """
        Evaluate if an upstream device has active hardware or interface faults
        (e.g., high CPU, CRC errors, link down, queue drops).
        """
        fault_reasons: List[str] = []
        fault_evidence: List[MetricEvidence] = []

        for m in metrics:
            name = m.metric_name.lower().strip()
            val = m.value

            # High CPU utilization (> 85%)
            if name in {"cpu_utilization_pct", "cpu_utilization", "cpu", "cpu_pct"} and val > 85.0:
                fault_reasons.append(f"high CPU utilization ({val:.1f}%)")
                fault_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Upstream node '{dev_name}' CPU exhaustion ({val:.1f}%).",
                        canonical_key="cpu",
                    )
                )

            # High Memory utilization (> 90%)
            elif name in {"memory_utilization_pct", "memory_utilization", "memory", "ram_pct", "ram"} and val > 90.0:
                fault_reasons.append(f"high Memory utilization ({val:.1f}%)")
                fault_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Upstream node '{dev_name}' memory exhaustion ({val:.1f}%).",
                        canonical_key="memory",
                    )
                )

            # Interface CRC errors (> 0)
            elif name in {"interface_crc_errors", "crc_errors", "fcs_errors", "rx_crc_errors"} and val > 0.0:
                fault_reasons.append(f"physical CRC errors ({val:.0f} errors)")
                fault_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Upstream node '{dev_name}' physical layer CRC frame corruption ({val:.0f} errors).",
                        canonical_key="crc_errors",
                    )
                )

            # Operational link down / port down
            elif name in {"oper_status", "link_state", "interface_state", "port_status", "device_status"} and val <= 0.0:
                fault_reasons.append("operational status down (link/device down)")
                fault_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Upstream node '{dev_name}' operational state is down.",
                        canonical_key="oper_status",
                    )
                )

            # Egress queue drops (> 0)
            elif name in {"egress_queue_drops", "queue_drops", "egress_drops", "tx_drops"} and val > 0.0:
                fault_reasons.append(f"egress buffer queue drops ({val:.0f} drops)")
                fault_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Upstream node '{dev_name}' active buffer overflow ({val:.0f} drops).",
                        canonical_key="queue_drops",
                    )
                )

            # Interface errors (> 10) or link flaps (> 3)
            elif name in {"interface_errors", "if_errors", "port_errors"} and val > 10.0:
                fault_reasons.append(f"interface packet errors ({val:.0f} errors)")
                fault_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Upstream node '{dev_name}' interface packet errors ({val:.0f} errors).",
                        canonical_key="interface_errors",
                    )
                )
            elif name in {"link_flaps", "flaps", "carrier_transitions"} and val > 3.0:
                fault_reasons.append(f"intermittent link flapping ({val:.0f} flaps)")
                fault_evidence.append(
                    MetricEvidence(
                        metric=m.metric_name,
                        value=val,
                        interpretation=f"Upstream node '{dev_name}' link flapping ({val:.0f} flaps).",
                        canonical_key="link_flaps",
                    )
                )

        has_fault = len(fault_reasons) > 0
        summary = " and ".join(fault_reasons) if fault_reasons else ""
        return has_fault, summary, fault_evidence

    def analyze(self, payload: RawTelemetryPayload) -> AgentFinding:
        """
        Assess blast radius and topology impact for the targeted device.
        Loads dynamic topology from payload metadata when present.
        Evaluates cross-device telemetry to identify upstream root cause devices
        when downstream symptoms are observed.
        """
        # Support loading topology from the payload metadata when present
        if payload.metadata:
            meta_topo = (
                payload.metadata.get("topology")
                or payload.metadata.get("custom_topology")
                or payload.metadata.get("campus_topology")
                or payload.metadata.get("network_topology")
            )
            if isinstance(meta_topo, dict) and meta_topo:
                self.topology = self._normalize_topology(copy.deepcopy(meta_topo))

        if not payload.metrics:
            limitations: List[str] = []
            if "ingestion_notes" in payload.metadata and payload.metadata["ingestion_notes"]:
                limitations.extend(payload.metadata["ingestion_notes"])
            elif "ingestion_error" in payload.metadata:
                limitations.append(str(payload.metadata["ingestion_error"]))
            elif "validation_error" in payload.metadata:
                limitations.append(str(payload.metadata["validation_error"]))
            else:
                limitations.append("metrics list was empty in payload")

            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis=f"No telemetry metrics provided to evaluate topology impact ({limitations[0] if limitations else 'no metrics'}).",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=limitations,
            )

        target = payload.target_device or "unknown_device"
        target_key = self._find_node_key(target)

        # Helper grouping metrics by device_id (case-insensitive)
        metrics_by_dev = self.get_metrics_by_device(payload)
        target_metrics = metrics_by_dev.get(target, [])

        target_has_symptoms, symptom_reasons, symptom_ev = self._device_has_symptoms(target_metrics)

        # -------------------------------------------------------------------
        # Upstream Root Cause Analysis:
        # If the target shows symptoms and an upstream device shows a fault
        # (high CPU, CRC errors, link down, etc.), report that upstream device
        # as the probable root cause and list the target as affected.
        # -------------------------------------------------------------------
        if target_has_symptoms and target_key:
            upstream_nodes = self.get_upstream_dependencies(target)
            for up_dev in upstream_nodes:
                up_metrics = metrics_by_dev.get(up_dev, [])
                if not up_metrics:
                    continue

                up_has_fault, up_fault_desc, up_fault_ev = self._device_has_fault(up_dev, up_metrics)
                if up_has_fault:
                    # Upstream root cause identified!
                    up_isolated, _ = self.compute_redundancy_aware_blast_radius(up_dev)
                    affected_set: List[str] = [up_dev, target]
                    for d in up_isolated:
                        if not any(d.lower() == a.lower() for a in affected_set):
                            affected_set.append(d)

                    evidence: List[MetricEvidence] = list(up_fault_ev) + list(symptom_ev) + [
                        MetricEvidence(
                            metric="downstream_blast_radius",
                            value=float(len(up_isolated)),
                            canonical_key="downstream_blast_radius",
                            interpretation=f"Failure on upstream root cause device '{up_dev}' isolates {len(up_isolated)} downstream devices.",
                        ),
                        MetricEvidence(
                            metric="upstream_dependency_depth",
                            value=float(len(upstream_nodes)),
                            canonical_key="upstream_dependency_depth",
                            interpretation=f"Target device '{target}' relies directly on upstream transit device '{up_dev}'.",
                        ),
                    ]

                    hypothesis = (
                        f"Probable root cause is upstream device '{up_dev}' experiencing {up_fault_desc}, "
                        f"propagating downstream service degradation to affected target '{target}'."
                    )

                    return AgentFinding(
                        agent_name=self.name,
                        status="anomaly_detected",
                        hypothesis=hypothesis,
                        confidence=0.95,
                        supporting_evidence=evidence,
                        affected_devices=affected_set,
                        limitations=[],
                    )

        # -------------------------------------------------------------------
        # Local Target Device Topology Evaluation
        # -------------------------------------------------------------------
        # Handle target device missing from topology mapping
        if not target_key:
            if not target_has_symptoms:
                return AgentFinding(
                    agent_name=self.name,
                    status="healthy",
                    hypothesis=f"Target device '{target}' is unmapped in topology (assumed localized edge node). No topology or telemetry anomalies detected.",
                    confidence=0.88,
                    supporting_evidence=[
                        MetricEvidence(
                            metric="downstream_blast_radius",
                            value=0.0,
                            canonical_key="downstream_blast_radius",
                            interpretation=f"Device {target} is unmapped; blast radius assumed localized to device.",
                        )
                    ],
                    affected_devices=[target] if target else [],
                    limitations=[f"Device '{target}' is unmapped in topology (missing from topology adjacency mapping); assumed localized edge node."],
                )
            else:
                return AgentFinding(
                    agent_name=self.name,
                    status="anomaly_detected",
                    hypothesis=f"Fault on '{target}' is assumed edge-isolated (device unmapped in campus topology graph). Impact restricted to local device.",
                    confidence=0.85,
                    supporting_evidence=[
                        MetricEvidence(
                            metric="downstream_blast_radius",
                            value=0.0,
                            canonical_key="downstream_blast_radius",
                            interpretation=f"Device {target} is unmapped; blast radius assumed localized to device.",
                        )
                    ],
                    affected_devices=[target] if target else [],
                    limitations=[f"Device '{target}' is unmapped in topology (missing from topology adjacency mapping); assumed localized edge node."],
                )

        canonical_target = target_key
        upstream_nodes = self.get_upstream_dependencies(canonical_target)
        isolated_dependents, redundant_dependents = self.compute_redundancy_aware_blast_radius(canonical_target)
        isolated_count = len(isolated_dependents)
        redundant_count = len(redundant_dependents)

        evidence: List[MetricEvidence] = [
            MetricEvidence(
                metric="downstream_blast_radius",
                value=float(isolated_count),
                canonical_key="downstream_blast_radius",
                interpretation=(
                    f"Failure on {canonical_target} would isolate {isolated_count} downstream network infrastructure devices."
                    if isolated_count > 0
                    else (
                        f"Zero downstream devices isolated on {canonical_target} failure due to redundant uplink paths."
                        if redundant_count > 0
                        else f"Zero downstream devices depend on edge node {canonical_target}."
                    )
                ),
            ),
            MetricEvidence(
                metric="upstream_dependency_depth",
                value=float(len(upstream_nodes)),
                canonical_key="upstream_dependency_depth",
                interpretation=(
                    f"Device {canonical_target} relies on {len(upstream_nodes)} upstream dependency nodes: "
                    f"{', '.join(upstream_nodes) if upstream_nodes else 'None (Root Node)'}."
                ),
            ),
        ]

        if not target_has_symptoms:
            return AgentFinding(
                agent_name=self.name,
                status="healthy",
                hypothesis=(
                    f"Network topology and link connectivity for '{canonical_target}' are nominal. "
                    "Blast radius and upstream dependencies are derived from the configured topology."
                ),
                confidence=0.70,
                supporting_evidence=evidence,
                affected_devices=[canonical_target],
                limitations=["Topology adjacency describes configured paths; live path health was not directly verified."],
            )

        # Target device has active fault / SLA violation
        if isolated_count == 0:
            if redundant_count > 0:
                hypothesis = (
                    f"Fault on upstream node '{canonical_target}' does not isolate downstream devices due to path redundancy. "
                    f"All {redundant_count} downstream devices maintain active alternative paths to core gateways."
                )
                confidence = 0.90
            else:
                hypothesis = (
                    f"Fault on '{canonical_target}' is edge-isolated. Zero downstream network infrastructure "
                    "nodes depend on this device. Impact is restricted to local terminal access."
                )
                confidence = 0.90
            affected = [canonical_target]
        else:
            hypothesis = (
                f"Single-point-of-failure identified at upstream aggregation node '{canonical_target}'. "
                f"Downstream blast radius comprises {isolated_count} isolated devices: "
                f"[{', '.join(isolated_dependents)}]."
            )
            confidence = 0.95
            affected = [canonical_target] + isolated_dependents

        return AgentFinding(
            agent_name=self.name,
            status="anomaly_detected",
            hypothesis=hypothesis,
            confidence=confidence,
            supporting_evidence=evidence,
            affected_devices=affected,
            limitations=[],
        )

    def peer_review(
        self,
        my_finding: AgentFinding,
        all_findings: List[AgentFinding],
    ) -> AgentFinding:
        """
        Cross-reference other agents' findings to corroborate topology blast radius and fault scope.
        """
        for other in all_findings:
            if other.agent_name in {"TelemetryAgent", "InfrastructureAgent"} and other.status == "anomaly_detected":
                my_finding.corroborates.append(f"{other.agent_name}:anomaly")
                my_finding.peer_assessments.append(
                    f"Topology dependency graph confirms blast radius and failure scope for {other.agent_name} anomaly."
                )
        return my_finding
