"""
core/schemas.py
Standardized Pydantic schemas for the NetCoop AI multi-agent diagnosis engine.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# 1. Telemetry Ingestion Schemas (Standardized Inputs)
# ---------------------------------------------------------------------------

class TelemetryMetric(BaseModel):
    """
    Represents an individual sanitized telemetry metric observation.
    """
    model_config = ConfigDict(extra="ignore")

    metric_name: str
    value: float
    unit: str
    timestamp: Optional[str] = None
    device_id: str


class RawTelemetryPayload(BaseModel):
    """
    Represents the full sanitized ingestion payload for a diagnostic scenario.
    """
    model_config = ConfigDict(extra="ignore")

    scenario_id: str
    target_device: str
    metrics: List[TelemetryMetric] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# 2. Inter-Agent Communication Schemas
# ---------------------------------------------------------------------------

class MetricEvidence(BaseModel):
    """
    Quantitative evidence extracted from metrics to support an agent's hypothesis.
    """
    model_config = ConfigDict(extra="ignore")

    metric: str
    value: float
    interpretation: str


class AgentFinding(BaseModel):
    """
    Diagnostic assessment emitted by individual domain agents
    (Telemetry, Infrastructure, Topology) and consumed by the Arbiter Agent.
    """
    model_config = ConfigDict(extra="ignore")

    agent_name: str
    status: Literal["healthy", "anomaly_detected", "insufficient_evidence"]
    hypothesis: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    supporting_evidence: List[MetricEvidence] = Field(default_factory=list)
    affected_devices: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 3. Final Consolidated Output (Challenge Schema)
# ---------------------------------------------------------------------------

class IncidentReport(BaseModel):
    """
    Final consolidated incident diagnosis report synthesized by the Arbiter.
    """
    model_config = ConfigDict(extra="ignore")

    incident_id: str
    status: Literal["diagnosed", "inconclusive", "insufficient_evidence"]
    suspected_root_cause: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    affected_devices: List[str] = Field(default_factory=list)
    supporting_evidence: List[MetricEvidence] = Field(default_factory=list)
    alternative_causes: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    evidence_sources: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
