"""
agents/topology_agent.py
Topology domain agent for NetCoop AI.
Maintains network hierarchy, computes downstream blast radius, and analyzes failure dependencies.
"""

from collections import deque
from typing import Dict, List, Optional, Set

from agents.base import BaseAgent
from core.schemas import AgentFinding, MetricEvidence, RawTelemetryPayload


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
    upstream dependency chains, and downstream blast radius.
    """

    def __init__(
        self,
        name: Optional[str] = None,
        custom_topology: Optional[Dict[str, Dict[str, List[str]]]] = None,
    ) -> None:
        super().__init__(name=name or "TopologyAgent")
        self.topology: Dict[str, Dict[str, List[str]]] = custom_topology if custom_topology is not None else CAMPUS_TOPOLOGY

    def get_upstream_dependencies(self, device: str) -> List[str]:
        """
        Traverse up the hierarchy using BFS to find all upstream transit nodes.
        """
        visited: Set[str] = set()
        queue: deque = deque([device])
        upstream_nodes: List[str] = []

        while queue:
            curr = queue.popleft()
            node_data = self.topology.get(curr)
            if not node_data:
                continue

            for parent in node_data.get("upstream", []):
                if parent not in visited:
                    visited.add(parent)
                    upstream_nodes.append(parent)
                    queue.append(parent)

        return upstream_nodes

    def compute_blast_radius(self, device: str) -> List[str]:
        """
        Compute downstream dependent devices using BFS traversal.
        """
        visited: Set[str] = set()
        queue: deque = deque([device])
        downstream_dependents: List[str] = []

        while queue:
            curr = queue.popleft()
            node_data = self.topology.get(curr)
            if not node_data:
                continue

            for child in node_data.get("downstream", []):
                if child not in visited:
                    visited.add(child)
                    downstream_dependents.append(child)
                    queue.append(child)

        return downstream_dependents

    def analyze(self, payload: RawTelemetryPayload) -> AgentFinding:
        """
        Assess blast radius and topology impact for the targeted device.
        """
        if not payload.metrics:
            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis="No telemetry metrics provided to evaluate topology impact.",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=["Empty metrics list in ingestion payload."],
            )

        target = payload.target_device
        if not target or target not in self.topology:
            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis=f"Target device '{target}' was not located in campus topology graph.",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[target] if target else [],
                limitations=[f"Device '{target}' missing from topology adjacency mapping."],
            )

        upstream_nodes = self.get_upstream_dependencies(target)
        downstream_dependents = self.compute_blast_radius(target)
        blast_radius_count = len(downstream_dependents)

        evidence: List[MetricEvidence] = [
            MetricEvidence(
                metric="downstream_blast_radius",
                value=float(blast_radius_count),
                interpretation=(
                    f"Fault on {target} potentially isolates {blast_radius_count} downstream network infrastructure devices."
                ),
            ),
            MetricEvidence(
                metric="upstream_dependency_depth",
                value=float(len(upstream_nodes)),
                interpretation=(
                    f"Device {target} relies on {len(upstream_nodes)} upstream dependency nodes: "
                    f"{', '.join(upstream_nodes) if upstream_nodes else 'None (Root Node)'}."
                ),
            ),
        ]

        affected = [target] + downstream_dependents

        if blast_radius_count == 0:
            hypothesis = (
                f"Fault on '{target}' is edge-isolated. Zero downstream network infrastructure "
                "nodes depend on this device. Impact is restricted to local terminal access."
            )
            confidence = 0.90
        else:
            hypothesis = (
                f"Single-point-of-failure identified at upstream aggregation node '{target}'. "
                f"Downstream blast radius comprises {blast_radius_count} devices: "
                f"[{', '.join(downstream_dependents)}]."
            )
            confidence = 0.95

        return AgentFinding(
            agent_name=self.name,
            status="anomaly_detected",
            hypothesis=hypothesis,
            confidence=confidence,
            supporting_evidence=evidence,
            affected_devices=affected,
            limitations=[],
        )
