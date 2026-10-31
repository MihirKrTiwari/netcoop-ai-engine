"""
core/coordinator.py
Orchestration layer for NetCoop AI multi-agent fault diagnosis engine.
Connects the full pipeline: Input Sanitization -> Domain Agents -> Peer Review -> Arbiter -> Reporter.
Maintains full message log with JSONL export capabilities and schema version enforcement.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from agents.arbiter_agent import ArbiterAgent
from agents.infrastructure_agent import InfrastructureAgent
from agents.reporter_agent import ReporterAgent
from agents.service_agent import ServiceAgent
from agents.telemetry_agent import TelemetryAgent
from agents.topology_agent import TopologyAgent
from agents.wireless_agent import WirelessAgent
from core.protocol import AgentMessage, MessageLog, check_schema_compatibility
from core.schemas import AgentFinding, IncidentReport, RawTelemetryPayload
from core.validator import validate_and_sanitize_payload

logger = logging.getLogger(__name__)


class NetCoopCoordinator:
    """
    Main orchestration engine executing end-to-end multi-agent network fault diagnosis.
    Coordinates data flow, inter-agent messaging, peer-review cross-referencing,
    and structured incident reporting.
    """

    def __init__(
        self,
        telemetry_agent: Optional[TelemetryAgent] = None,
        infrastructure_agent: Optional[InfrastructureAgent] = None,
        topology_agent: Optional[TopologyAgent] = None,
        wireless_agent: Optional[WirelessAgent] = None,
        service_agent: Optional[ServiceAgent] = None,
        arbiter_agent: Optional[ArbiterAgent] = None,
        reporter_agent: Optional[ReporterAgent] = None,
        parallel_execution: bool = True,
    ) -> None:
        self.telemetry_agent = telemetry_agent if telemetry_agent is not None else TelemetryAgent()
        self.infrastructure_agent = infrastructure_agent if infrastructure_agent is not None else InfrastructureAgent()
        self.topology_agent = topology_agent if topology_agent is not None else TopologyAgent()
        self.wireless_agent = wireless_agent if wireless_agent is not None else WirelessAgent()
        self.service_agent = service_agent if service_agent is not None else ServiceAgent()
        self.arbiter_agent = arbiter_agent if arbiter_agent is not None else ArbiterAgent()
        self.reporter_agent = reporter_agent if reporter_agent is not None else ReporterAgent()
        self.parallel_execution = parallel_execution
        self.message_log: MessageLog = MessageLog()

    def _safe_analyze(
        self, agent: Any, payload: RawTelemetryPayload, fallback_agent_name: str
    ) -> AgentFinding:
        """
        Execute an agent's analyze method wrapped in try/except.
        Yields an insufficient_evidence finding with the error recorded as a limitation,
        preventing any agent failure from crashing the pipeline.
        """
        agent_name = getattr(agent, "name", fallback_agent_name)
        try:
            finding = agent.analyze(payload)
            self.message_log.record(
                sender=agent_name,
                recipient="coordinator",
                message_type="agent_finding",
                payload={
                    "agent_name": finding.agent_name,
                    "status": finding.status,
                    "hypothesis": finding.hypothesis,
                    "confidence": finding.confidence,
                    "evidence_count": len(finding.supporting_evidence),
                },
            )
            return finding
        except Exception as err:
            logger.error("Agent '%s' failed during analysis: %s", agent_name, err, exc_info=True)
            self.message_log.record(
                sender=agent_name,
                recipient="coordinator",
                message_type="error",
                payload={"error": str(err), "agent": agent_name},
            )
            return AgentFinding(
                agent_name=agent_name,
                status="insufficient_evidence",
                hypothesis=f"Diagnostic failure in {agent_name}: {err}",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[payload.target_device] if payload.target_device else [],
                limitations=[f"Agent execution error in {agent_name}: {err}"],
            )

    def _execute_domain_agents(self, payload: RawTelemetryPayload) -> List[AgentFinding]:
        """
        Execute domain diagnostic agents either in parallel worker threads or sequentially.
        Guarantees that individual agent exceptions never crash the pipeline.
        """
        if self.parallel_execution:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_telemetry = executor.submit(
                    self._safe_analyze, self.telemetry_agent, payload, "TelemetryAgent"
                )
                future_infra = executor.submit(
                    self._safe_analyze, self.infrastructure_agent, payload, "InfrastructureAgent"
                )
                future_topo = executor.submit(
                    self._safe_analyze, self.topology_agent, payload, "TopologyAgent"
                )
                future_wireless = executor.submit(
                    self._safe_analyze, self.wireless_agent, payload, "WirelessAgent"
                )
                future_service = executor.submit(
                    self._safe_analyze, self.service_agent, payload, "ServiceAgent"
                )

                findings: List[AgentFinding] = [
                    future_telemetry.result(),
                    future_infra.result(),
                    future_topo.result(),
                    future_wireless.result(),
                    future_service.result(),
                ]
            return findings

        return [
            self._safe_analyze(self.telemetry_agent, payload, "TelemetryAgent"),
            self._safe_analyze(self.infrastructure_agent, payload, "InfrastructureAgent"),
            self._safe_analyze(self.topology_agent, payload, "TopologyAgent"),
            self._safe_analyze(self.wireless_agent, payload, "WirelessAgent"),
            self._safe_analyze(self.service_agent, payload, "ServiceAgent"),
        ]

    def _execute_peer_review(self, findings: List[AgentFinding]) -> List[AgentFinding]:
        """
        Execute peer review cross-referencing between domain agents.
        Each agent inspects findings from other agents and attaches corroboration notes.
        """
        agents = [
            self.telemetry_agent,
            self.infrastructure_agent,
            self.topology_agent,
            self.wireless_agent,
            self.service_agent,
        ]
        finding_by_name = {f.agent_name: f for f in findings}
        reviewed: List[AgentFinding] = []

        for agent in agents:
            orig = finding_by_name.get(agent.name)
            if orig is not None:
                try:
                    res = agent.peer_review(orig, findings)
                    reviewed.append(res)
                    if res.peer_assessments or res.corroborates:
                        self.message_log.record(
                            sender=agent.name,
                            recipient="coordinator",
                            message_type="peer_review",
                            payload={
                                "agent": agent.name,
                                "corroborates": res.corroborates,
                                "peer_assessments": res.peer_assessments,
                            },
                        )
                except Exception as exc:
                    logger.warning("Peer review error for %s: %s", agent.name, exc)
                    reviewed.append(orig)
            elif orig is not None:
                reviewed.append(orig)

        return reviewed if reviewed else findings

    def run(
        self,
        raw_input: Union[Dict[str, Any], RawTelemetryPayload, str, Any],
        incident_id: Optional[str] = None,
    ) -> IncidentReport:
        """
        Execute the end-to-end diagnosis pipeline on a raw payload dictionary,
        RawTelemetryPayload object, or JSON string.

        Args:
            raw_input: Raw dictionary, RawTelemetryPayload, or JSON string representing incoming telemetry.
            incident_id: Optional override for the incident report identifier.

        Returns:
            IncidentReport matching the challenge schema.
        """
        inc_id = incident_id if incident_id else f"INC-{uuid.uuid4().hex[:8].upper()}"
        self.message_log = MessageLog(incident_id=inc_id)

        # 1. Ingestion & Validation
        if isinstance(raw_input, RawTelemetryPayload):
            sanitized_payload = raw_input
        elif isinstance(raw_input, str):
            cleaned_input = raw_input.lstrip("\ufeff").strip()
            if not cleaned_input:
                raw_dict = {
                    "scenario_id": "empty_input",
                    "metrics": [],
                    "metadata": {"ingestion_notes": ["input JSON string is empty"]},
                }
            else:
                try:
                    raw_dict = json.loads(cleaned_input)
                except Exception as json_err:
                    logger.error("Failed to parse JSON string: %s", json_err)
                    raw_dict = {
                        "scenario_id": "malformed_json_str",
                        "metrics": [],
                        "metadata": {"ingestion_notes": [f"malformed JSON string: {json_err}"]},
                    }
            sanitized_payload = validate_and_sanitize_payload(raw_dict)
        else:
            sanitized_payload = validate_and_sanitize_payload(raw_input)

        # Check schema version compatibility
        raw_version = sanitized_payload.metadata.get("schema_version")
        is_compat, version_note = check_schema_compatibility(raw_version)
        if not is_compat:
            sanitized_payload.metadata.setdefault("ingestion_notes", []).append(version_note)

        ingestion_notes: List[str] = list(sanitized_payload.metadata.get("ingestion_notes", []))

        # Log Ingestion Event
        self.message_log.record(
            sender="ingestion_validator",
            recipient="coordinator",
            message_type="telemetry_ingest",
            payload={
                "scenario_id": sanitized_payload.scenario_id,
                "target_device": sanitized_payload.target_device,
                "metrics_count": len(sanitized_payload.metrics),
                "metadata": sanitized_payload.metadata,
            },
        )

        # 2. Multi-Agent Domain Analysis
        raw_findings: List[AgentFinding] = self._execute_domain_agents(sanitized_payload)

        # 3. Peer-Review Step
        findings: List[AgentFinding] = self._execute_peer_review(raw_findings)

        # 4. Arbitration and Conflict Resolution
        self.message_log.record(
            sender="coordinator",
            recipient="ArbiterAgent",
            message_type="arbiter_request",
            payload={"findings_count": len(findings)},
        )

        arbitration = self.arbiter_agent.arbitrate(
            findings=findings,
            target_device=sanitized_payload.target_device,
            ingestion_notes=ingestion_notes,
        )

        self.message_log.record(
            sender="ArbiterAgent",
            recipient="coordinator",
            message_type="arbiter_verdict",
            payload={
                "status": arbitration.status,
                "root_cause": arbitration.suspected_root_cause,
                "root_cause_category": arbitration.root_cause_category,
                "confidence": arbitration.confidence,
                "rule_id": arbitration.rule_id,
            },
        )

        # 5. Final Incident Reporting
        report: IncidentReport = self.reporter_agent.generate_report(
            arbitration=arbitration,
            incident_id=inc_id,
            scenario_id=sanitized_payload.scenario_id,
            ingestion_notes=ingestion_notes,
        )

        return report

    def run_from_file(
        self,
        filepath: str,
        incident_id: Optional[str] = None,
    ) -> IncidentReport:
        """
        Load telemetry data from a JSON file and execute the diagnosis pipeline.
        Gracefully handles malformed JSON, empty files, UTF-8 BOM, and unreadable files.
        """
        try:
            with open(filepath, "r", encoding="utf-8-sig") as f:
                content = f.read()
        except Exception as file_err:
            logger.error("Failed to read file '%s': %s", filepath, file_err)
            payload = validate_and_sanitize_payload({
                "scenario_id": "unreadable_file",
                "metrics": [],
                "metadata": {"ingestion_notes": [f"failed to read file '{filepath}': {file_err}"]},
            })
            return self.run(raw_input=payload, incident_id=incident_id)

        if not content.strip():
            logger.warning("Empty file provided: %s", filepath)
            payload = validate_and_sanitize_payload({
                "scenario_id": "empty_file",
                "metrics": [],
                "metadata": {"ingestion_notes": [f"file '{filepath}' is empty"]},
            })
            return self.run(raw_input=payload, incident_id=incident_id)

        return self.run(raw_input=content, incident_id=incident_id)

    def get_message_log(self) -> MessageLog:
        """Return the coordinator's recorded inter-agent message log."""
        return self.message_log

    def export_message_log(self, filepath: Union[str, Path]) -> None:
        """Write the coordinator's message log to a JSON Lines file."""
        self.message_log.export_jsonl(filepath)
