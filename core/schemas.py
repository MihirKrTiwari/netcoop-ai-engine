# Define Pydantic models for validated inputs, agent findings, messages, and reports.

"""
core/schemas.py
Standardized Pydantic schemas for the NetCoop AI multi-agent diagnosis engine.
"""

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# 1. Telemetry Ingestion Schemas (Standardized Inputs)
# ---------------------------------------------------------------------------

class TelemetryMetric(BaseModel):
    metric_name: str
    value: float
    unit: str
    timestamp: Optional[str] = None
    device_id: str


class RawTelemetryPayload(BaseModel):
    scenario_id: str
    target_device: str
    metrics: List[TelemetryMetric] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# 2. Inter-Agent Communication Schemas
# ---------------------------------------------------------------------------

class MetricEvidence(BaseModel):
    metric: str
    value: float
    interpretation: str


class AgentFinding(BaseModel):
    """
    Emitted by individual domain agents (Telemetry, Infra, Topology)
    and consumed by the Arbiter Agent.
    """
    agent_name: str
    status: Literal["healthy", "anomaly_detected", "insufficient_evidence"]
    hypothesis: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    supporting_evidence: List[MetricEvidence] = Field(default_factory=list)
    affected_devices: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 3. Final Consolidated Output (Required Challenge Schema)
# ---------------------------------------------------------------------------

class IncidentReport(BaseModel):
    """
    Standard schema compliance matching Section 6 of the NetCoop problem statement.
    """
    incident_id: str
    status: Literal["diagnosed", "inconclusive", "insufficient_evidence"]
    suspected_root_cause: str
    confidence: float = Field(ge=0.0, le=1.0)
    affected_devices: List[str]
    supporting_evidence: List[MetricEvidence]
    alternative_causes: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    evidence_sources: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)