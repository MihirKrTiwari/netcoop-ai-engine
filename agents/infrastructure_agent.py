"""
agents/infrastructure_agent.py
Infrastructure domain agent for NetCoop AI.
Monitors node-level health: CPU, memory, buffer queue drops, and physical interface CRC errors.
Filters metrics for target_device and selects newest samples by timestamp.
"""

from typing import Dict, List, Optional
from datetime import datetime

from agents.base import BaseAgent
from core.schemas import AgentFinding, MetricEvidence, RawTelemetryPayload, TelemetryMetric
from core.timeutils import is_newer

_is_newer = is_newer


class InfrastructureAgent(BaseAgent):
    """
    Analyzes hardware resources, control plane state, forwarding ASIC buffers,
    and Layer 1/2 physical interface health to diagnose node-level faults.
    """

    CPU_THRESHOLD_PCT: float = 85.0
    MEMORY_THRESHOLD_PCT: float = 90.0
    QUEUE_DROPS_THRESHOLD: float = 0.0
    CRC_ERRORS_THRESHOLD: float = 0.0
    INTERFACE_ERRORS_THRESHOLD: float = 0.0
    LINK_FLAPS_THRESHOLD: float = 3.0
    OPER_STATUS_DOWN_VAL: float = 0.0
    DEVICE_STATUS_DOWN_VAL: float = 0.0

    # Recognized unit variations
    _COUNT_UNITS = frozenset({"count", "errors", "drops", "flaps", "events", "packets", "dimensionless", ""})
    _PERCENT_UNITS = frozenset({"%", "pct", "percent", "percentage", "ratio", "fraction"})
    _STATE_UNITS = frozenset({"state", "status", "binary", "dimensionless", "", "bool"})

    def __init__(self, name: Optional[str] = None) -> None:
        super().__init__(name=name or "InfrastructureAgent")

    def _extract_canonical_metrics(
        self,
        metrics: List[TelemetryMetric],
        target_device: Optional[str] = None,
    ) -> Dict[str, TelemetryMetric]:
        """
        Normalize metric name variations to canonical infrastructure keys.
        Filters specifically for target_device and retains newest timestamped sample.
        """
        mapping: Dict[str, TelemetryMetric] = {}
        for m in metrics:
            if target_device and m.device_id and m.device_id.strip().lower() != target_device.strip().lower():
                continue

            name_clean = m.metric_name.lower().strip()
            canonical_key: Optional[str] = None

            if name_clean in {"cpu_utilization_pct", "cpu_utilization", "cpu", "cpu_pct"}:
                canonical_key = "cpu"
            elif name_clean in {"memory_utilization_pct", "memory_utilization", "memory", "ram_pct", "memory_pct", "ram"}:
                canonical_key = "memory"
            elif name_clean in {"egress_queue_drops", "queue_drops", "egress_drops", "tx_drops"}:
                canonical_key = "queue_drops"
            elif name_clean in {"interface_crc_errors", "crc_errors", "fcs_errors", "rx_crc_errors"}:
                canonical_key = "crc_errors"
            elif name_clean in {"interface_errors", "if_errors", "port_errors", "rx_errors", "tx_errors", "packet_errors"}:
                canonical_key = "interface_errors"
            elif name_clean in {"link_flaps", "carrier_transitions", "flaps", "interface_flaps", "port_flaps"}:
                canonical_key = "link_flaps"
            elif name_clean in {"oper_status", "link_state", "if_oper_status", "port_status", "interface_state"}:
                canonical_key = "oper_status"
            elif name_clean in {"device_status", "node_status", "system_health", "device_state", "chassis_status"}:
                canonical_key = "device_status"

            if canonical_key is not None:
                if canonical_key not in mapping or _is_newer(m, mapping[canonical_key]):
                    mapping[canonical_key] = m

        return mapping

    def analyze(self, payload: RawTelemetryPayload) -> AgentFinding:
        """
        Diagnose infrastructure anomalies distinguishing between control plane exhaustion,
        buffer overflows, physical layer degradation, and interface/device operational status.
        """
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
                hypothesis=f"No infrastructure telemetry metrics provided in payload ({limitations[0] if limitations else 'no metrics'}).",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=limitations,
            )

        infra_map = self._extract_canonical_metrics(payload.metrics, target_device=payload.target_device)
        if not infra_map:
            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis=f"No recognizable infrastructure metrics (CPU, RAM, queue drops, CRC errors, interface health) found for '{payload.target_device}'.",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=["No recognized hardware or interface metrics matched for target device."],
            )

        evidence: List[MetricEvidence] = []
        limitations: List[str] = []
        high_cpu = False
        high_memory = False
        buffer_overflow = False
        crc_degradation = False
        has_if_errors = False
        has_link_flaps = False
        is_link_down = False
        is_device_down = False

        # 1. CPU Utilization Check
        cpu_metric = infra_map.get("cpu")
        if cpu_metric is not None:
            unit_clean = cpu_metric.unit.lower().strip()
            norm_val = cpu_metric.value
            if unit_clean in {"ratio", "fraction"}:
                norm_val = norm_val * 100.0

            if unit_clean in self._PERCENT_UNITS or unit_clean in {"", "dimensionless"}:
                high_cpu = norm_val > self.CPU_THRESHOLD_PCT
                evidence.append(
                    MetricEvidence(
                        metric=cpu_metric.metric_name,
                        value=norm_val,
                        canonical_key="cpu",
                        interpretation=(
                            f"CPU utilization ({norm_val:.1f}%) exceeds critical threshold ({self.CPU_THRESHOLD_PCT}%)."
                            if high_cpu
                            else f"CPU utilization ({norm_val:.1f}%) is healthy."
                        ),
                    )
                )
            else:
                limitations.append(f"CPU unit '{cpu_metric.unit}' unverified; expected percentage.")

        # 2. Memory Utilization Check
        mem_metric = infra_map.get("memory")
        if mem_metric is not None:
            unit_clean = mem_metric.unit.lower().strip()
            norm_val = mem_metric.value
            if unit_clean in {"ratio", "fraction"}:
                norm_val = norm_val * 100.0

            if unit_clean in self._PERCENT_UNITS or unit_clean in {"", "dimensionless"}:
                high_memory = norm_val > self.MEMORY_THRESHOLD_PCT
                evidence.append(
                    MetricEvidence(
                        metric=mem_metric.metric_name,
                        value=norm_val,
                        canonical_key="memory",
                        interpretation=(
                            f"Memory utilization ({norm_val:.1f}%) exceeds safety threshold ({self.MEMORY_THRESHOLD_PCT}%)."
                            if high_memory
                            else f"Memory utilization ({norm_val:.1f}%) is within safe bounds."
                        ),
                    )
                )
            else:
                limitations.append(f"Memory unit '{mem_metric.unit}' unverified; expected percentage.")

        # 3. Egress Queue Drops Check
        drops_metric = infra_map.get("queue_drops")
        if drops_metric is not None:
            unit_clean = drops_metric.unit.lower().strip()
            if unit_clean in self._COUNT_UNITS:
                buffer_overflow = drops_metric.value > self.QUEUE_DROPS_THRESHOLD
                evidence.append(
                    MetricEvidence(
                        metric=drops_metric.metric_name,
                        value=drops_metric.value,
                        canonical_key="queue_drops",
                        interpretation=(
                            f"Active egress queue drops detected ({drops_metric.value:.0f} drops), indicating buffer overflow."
                            if buffer_overflow
                            else "No egress queue drops recorded."
                        ),
                    )
                )
            else:
                limitations.append(f"Queue drops unit '{drops_metric.unit}' unverified; expected count.")

        # 4. Interface CRC Errors Check
        crc_metric = infra_map.get("crc_errors")
        if crc_metric is not None:
            unit_clean = crc_metric.unit.lower().strip()
            if unit_clean in self._COUNT_UNITS:
                crc_degradation = crc_metric.value > self.CRC_ERRORS_THRESHOLD
                evidence.append(
                    MetricEvidence(
                        metric=crc_metric.metric_name,
                        value=crc_metric.value,
                        canonical_key="crc_errors",
                        interpretation=(
                            f"Physical CRC frame check errors detected ({crc_metric.value:.0f} errors), indicating cabling or optical transceiver degradation."
                            if crc_degradation
                            else "No physical CRC errors detected."
                        ),
                    )
                )
            else:
                limitations.append(f"CRC errors unit '{crc_metric.unit}' unverified; expected count.")

        # 5. Interface Errors Check
        if_errors_metric = infra_map.get("interface_errors")
        if if_errors_metric is not None:
            unit_clean = if_errors_metric.unit.lower().strip()
            if unit_clean in self._COUNT_UNITS:
                has_if_errors = if_errors_metric.value > self.INTERFACE_ERRORS_THRESHOLD
                evidence.append(
                    MetricEvidence(
                        metric=if_errors_metric.metric_name,
                        value=if_errors_metric.value,
                        canonical_key="interface_errors",
                        interpretation=(
                            f"Interface packet errors detected ({if_errors_metric.value:.0f} errors), indicating physical framing defects or interface transceiver degradation."
                            if has_if_errors
                            else f"Interface error counters are zero ({if_errors_metric.value:.0f})."
                        ),
                    )
                )
            else:
                limitations.append(f"Interface errors unit '{if_errors_metric.unit}' unverified; expected count.")

        # 6. Link Flaps Check (> 3 flaps indicates instability)
        link_flaps_metric = infra_map.get("link_flaps")
        if link_flaps_metric is not None:
            unit_clean = link_flaps_metric.unit.lower().strip()
            if unit_clean in self._COUNT_UNITS:
                has_link_flaps = link_flaps_metric.value > self.LINK_FLAPS_THRESHOLD
                evidence.append(
                    MetricEvidence(
                        metric=link_flaps_metric.metric_name,
                        value=link_flaps_metric.value,
                        canonical_key="link_flaps",
                        interpretation=(
                            f"Link flap counter ({link_flaps_metric.value:.0f} flaps) exceeds threshold ({self.LINK_FLAPS_THRESHOLD:.0f}), indicating link instability or auto-negotiation failure."
                            if has_link_flaps
                            else f"Link flap count ({link_flaps_metric.value:.0f}) is within tolerance."
                        ),
                    )
                )
            else:
                limitations.append(f"Link flaps unit '{link_flaps_metric.unit}' unverified; expected count.")

        # 7. Oper Status / Link State Check (0 = down)
        oper_metric = infra_map.get("oper_status")
        if oper_metric is not None:
            unit_clean = oper_metric.unit.lower().strip()
            if unit_clean in self._STATE_UNITS:
                is_link_down = oper_metric.value == self.OPER_STATUS_DOWN_VAL
                evidence.append(
                    MetricEvidence(
                        metric=oper_metric.metric_name,
                        value=oper_metric.value,
                        canonical_key="oper_status",
                        interpretation=(
                            f"Operational link status is DOWN (state={oper_metric.value:.0f}), indicating port shutdown or carrier signal loss."
                            if is_link_down
                            else f"Operational link status is UP (state={oper_metric.value:.0f})."
                        ),
                    )
                )
            else:
                limitations.append(f"Oper status unit '{oper_metric.unit}' unverified; expected state.")

        # 8. Device Status Check (0 = down / degraded)
        dev_stat_metric = infra_map.get("device_status")
        if dev_stat_metric is not None:
            unit_clean = dev_stat_metric.unit.lower().strip()
            if unit_clean in self._STATE_UNITS:
                is_device_down = dev_stat_metric.value == self.DEVICE_STATUS_DOWN_VAL
                evidence.append(
                    MetricEvidence(
                        metric=dev_stat_metric.metric_name,
                        value=dev_stat_metric.value,
                        canonical_key="device_status",
                        interpretation=(
                            f"Device operational status indicates DOWN/DEGRADED (status={dev_stat_metric.value:.0f})."
                            if is_device_down
                            else f"Device operational status is UP (status={dev_stat_metric.value:.0f})."
                        ),
                    )
                )
            else:
                limitations.append(f"Device status unit '{dev_stat_metric.unit}' unverified; expected state.")

        affected = [payload.target_device] if payload.target_device else []

        has_any_anomaly = (
            high_cpu or high_memory or buffer_overflow or crc_degradation
            or has_if_errors or has_link_flaps or is_link_down or is_device_down
        )

        # Classification heuristics
        if not has_any_anomaly:
            has_cpu_or_memory = ("cpu" in infra_map) or ("memory" in infra_map)

            expected_metrics = ["cpu", "memory", "queue_drops", "crc_errors"]
            missing_metrics = [m for m in expected_metrics if m not in infra_map]
            if missing_metrics:
                limitations.append(f"Missing infrastructure metrics: {', '.join(missing_metrics)}.")

            if not has_cpu_or_memory:
                return AgentFinding(
                    agent_name=self.name,
                    status="insufficient_evidence",
                    hypothesis=f"Insufficient infrastructure telemetry to confirm normal node health for {payload.target_device}; requires at least CPU or memory utilization.",
                    confidence=0.45,
                    supporting_evidence=evidence,
                    affected_devices=affected,
                    limitations=limitations or ["Requires at least CPU or memory utilization metric."],
                )

            return AgentFinding(
                agent_name=self.name,
                status="healthy",
                hypothesis=f"Hardware and physical interface infrastructure on {payload.target_device} are operating normally.",
                confidence=0.92,
                supporting_evidence=evidence,
                affected_devices=affected,
                limitations=limitations,
            )

        diagnoses: List[str] = []
        confidence = 0.85

        if is_device_down:
            diagnoses.append(
                f"Node shutdown or critical hardware failure on {payload.target_device} (device_status={dev_stat_metric.value:.0f})."
            )
            confidence = 0.96
        elif is_link_down:
            diagnoses.append(
                f"Physical interface operational link-down failure on {payload.target_device} (oper_status={oper_metric.value:.0f})."
            )
            confidence = 0.95
        elif has_link_flaps:
            diagnoses.append(
                f"Severe link flapping detected on {payload.target_device} ({link_flaps_metric.value:.0f} flaps > threshold {self.LINK_FLAPS_THRESHOLD:.0f})."
            )
            confidence = 0.93
        elif crc_degradation and buffer_overflow:
            diagnoses.append(
                f"Concurrent physical layer degradation ({crc_metric.value:.0f} CRC errors) "
                f"and egress buffer overflow ({drops_metric.value:.0f} drops) on {payload.target_device}. "
                "Cabling faults may be causing packet retransmissions leading to downstream queue exhaustion."
            )
            confidence = 0.95
        elif crc_degradation or has_if_errors:
            err_count = (crc_metric.value if crc_metric else 0.0) + (if_errors_metric.value if if_errors_metric else 0.0)
            diagnoses.append(
                f"Physical layer cabling or interface transceiver degradation on {payload.target_device}. "
                f"Accumulation of errors ({err_count:.0f} CRC/packet errors) indicates frame corruption at Layer 1/2."
            )
            confidence = 0.92
        elif buffer_overflow and (high_cpu or high_memory):
            diagnoses.append(
                f"Hardware resource saturation and packet forwarding congestion on {payload.target_device}. "
                "Control plane exhaustion is compounding ASIC buffer queue drops."
            )
            confidence = 0.90
        elif buffer_overflow:
            diagnoses.append(
                f"Forwarding buffer overflow detected on {payload.target_device}. "
                f"Active egress queue drops ({drops_metric.value:.0f}) confirm micro-burst or sustained link congestion."
            )
            confidence = 0.88
        elif high_cpu and high_memory:
            diagnoses.append(
                f"Critical control plane resource exhaustion on {payload.target_device}. "
                f"Both CPU ({cpu_metric.value:.1f}%) and Memory ({mem_metric.value:.1f}%) exceed operational ceilings."
            )
            confidence = 0.94
        elif high_cpu:
            diagnoses.append(
                f"Control plane CPU spike on {payload.target_device} ({cpu_metric.value:.1f}%). "
                "Risk of control plane starvation or routing engine delays."
            )
            confidence = 0.85
        elif high_memory:
            diagnoses.append(
                f"Severe memory exhaustion on {payload.target_device} ({mem_metric.value:.1f}%). "
                "Potential memory leak or oversized routing/state tables."
            )
            confidence = 0.85

        return AgentFinding(
            agent_name=self.name,
            status="anomaly_detected",
            hypothesis=" ".join(diagnoses),
            confidence=confidence,
            supporting_evidence=evidence,
            affected_devices=affected,
            limitations=limitations,
        )
