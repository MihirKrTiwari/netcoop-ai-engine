"""
agents/base.py
Base abstraction for NetCoop AI diagnostic domain agents.
"""

from abc import ABC, abstractmethod
from typing import Optional

from core.schemas import AgentFinding, RawTelemetryPayload


class BaseAgent(ABC):
    """
    Abstract base class for all NetCoop AI diagnostic domain agents.
    Subclasses evaluate domain-specific telemetry and return an AgentFinding.
    """

    def __init__(self, name: Optional[str] = None) -> None:
        self.name: str = name if name else self.__class__.__name__

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

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name='{self.name}')>"
