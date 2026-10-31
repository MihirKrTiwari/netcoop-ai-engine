"""
agents/base.py
Base abstraction for NetCoop AI diagnostic domain agents.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from core.schemas import (
    AgentFinding,
    CaseInsensitiveDict,
    RawTelemetryPayload,
    TelemetryMetric,
    get_metrics_by_device,
    get_metrics_by_device_id,
)


class BaseAgent(ABC):
    """
    Abstract base class for all NetCoop AI diagnostic domain agents.
    Subclasses evaluate domain-specific telemetry and return an AgentFinding.
    """

    def __init__(self, name: Optional[str] = None) -> None:
        self.name: str = name if name else self.__class__.__name__

    @staticmethod
    def get_metrics_by_device(payload: RawTelemetryPayload) -> CaseInsensitiveDict:
        """
        Group metrics by device_id with case-insensitive dictionary access.
        """
        return get_metrics_by_device(payload)

    @staticmethod
    def get_metrics_by_device_id(payload: RawTelemetryPayload) -> CaseInsensitiveDict:
        """
        Alias for get_metrics_by_device.
        """
        return get_metrics_by_device_id(payload)

    @abstractmethod
    def analyze(self, payload: RawTelemetryPayload) -> AgentFinding:
        """
        Analyze a validated telemetry payload and generate domain findings.

        Args:
            payload: Validated and sanitized telemetry payload.

        Returns:
            AgentFinding containing health assessment, hypothesis, confidence score,
            supporting metric evidence, affected devices, and limitations.
        """
        raise NotImplementedError("Subclasses of BaseAgent must implement analyze().")

    def peer_review(
        self,
        my_finding: AgentFinding,
        all_findings: List[AgentFinding],
    ) -> AgentFinding:
        """
        Optional peer-review callback allowing an agent to cross-reference other agents'
        findings and attach assessments or corroborations.
        """
        return my_finding

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name='{self.name}')>"
