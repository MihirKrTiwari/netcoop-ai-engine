"""
core/protocol.py
Inter-agent communication protocol and message envelope for NetCoop AI.
Provides deterministic structured message contracts for logging, tracing,
schema version negotiation, and peer-review interactions between diagnostic agents.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import threading
from typing import Any, Dict, List, Literal, Optional, Tuple, Union
import uuid

from pydantic import BaseModel, ConfigDict, Field

CURRENT_PROTOCOL_VERSION = "1.0"
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0", "v1.0", "1.0.0", "v1", "netcoop-v1", "1.1"})
SUPPORTED_PROTOCOL_VERSIONS = SUPPORTED_SCHEMA_VERSIONS


class AgentMessage(BaseModel):
    """
    Standardized envelope wrapping all inter-agent messages and coordinator events.
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    message_id: str = Field(default_factory=lambda: f"msg-{uuid.uuid4().hex[:12]}")
    incident_id: str = Field(default="")
    correlation_id: str = Field(default="")
    schema_version: str = CURRENT_PROTOCOL_VERSION
    message_type: str = Field(
        description="Type of message: telemetry_ingest, agent_finding, peer_review, arbiter_request, arbiter_verdict, error"
    )
    sender: str
    recipient: str
    sequence_number: int = Field(default=0)
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    )
    timestamp: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.incident_id and self.correlation_id:
            self.incident_id = self.correlation_id
        elif not self.correlation_id and self.incident_id:
            self.correlation_id = self.incident_id
        if not self.timestamp:
            self.timestamp = self.created_at

    def to_json(self) -> str:
        """Serialize message envelope to JSON string."""
        return self.model_dump_json(indent=None)


class MessageLog:
    """
    Ordered in-memory container for agent messages with JSONL export/import capabilities.
    """
    def __init__(self, incident_id: Optional[str] = None) -> None:
        self.incident_id: str = incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"
        self.messages: List[AgentMessage] = []
        self._seq_counter: int = 0
        self._lock = threading.Lock()

    def record(
        self,
        sender: str,
        recipient: str,
        message_type: str,
        payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        schema_version: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> AgentMessage:
        """Construct and append an AgentMessage to the log with auto-incrementing sequence number."""
        with self._lock:
            self._seq_counter += 1
            inc_id = incident_id or correlation_id or self.incident_id
            msg = AgentMessage(
                message_id=f"msg-{uuid.uuid4().hex[:12]}",
                incident_id=inc_id,
                correlation_id=inc_id,
                schema_version=schema_version or CURRENT_PROTOCOL_VERSION,
                message_type=message_type,
                sender=sender,
                recipient=recipient,
                sequence_number=self._seq_counter,
                payload=payload,
            )
            self.messages.append(msg)
            return msg

    def add(
        self,
        sender: str,
        recipient: str,
        message_type: str,
        payload: Dict[str, Any],
        incident_id: Optional[str] = None,
        schema_version: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> AgentMessage:
        """Convenience alias for record()."""
        return self.record(
            sender=sender,
            recipient=recipient,
            message_type=message_type,
            payload=payload,
            incident_id=incident_id,
            schema_version=schema_version,
            correlation_id=correlation_id,
        )

    def get_messages(
        self,
        sender: Optional[str] = None,
        recipient: Optional[str] = None,
        message_type: Optional[str] = None,
    ) -> List[AgentMessage]:
        """Filter logged messages by sender, recipient, or message type."""
        results = self.messages
        if sender:
            results = [m for m in results if m.sender == sender]
        if recipient:
            results = [m for m in results if m.recipient == recipient]
        if message_type:
            results = [m for m in results if m.message_type == message_type]
        return results

    def export_jsonl(self, filepath: Union[str, Path]) -> None:
        """Write all logged messages to a JSON Lines file."""
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as f:
            for msg in self.messages:
                f.write(msg.model_dump_json() + "\n")

    @classmethod
    def load_jsonl(cls, filepath: Union[str, Path]) -> "MessageLog":
        """Load messages from a JSON Lines file."""
        source = Path(filepath)
        log = cls()
        with source.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    data = json.loads(stripped)
                    msg = AgentMessage.model_validate(data)
                    log.messages.append(msg)
                    if msg.sequence_number > log._seq_counter:
                        log._seq_counter = msg.sequence_number
        if log.messages:
            log.incident_id = log.messages[0].incident_id
        return log


def export_message_log(log: MessageLog, filepath: Union[str, Path]) -> None:
    """Helper function to export a MessageLog to a JSONL file."""
    log.export_jsonl(filepath)


def load_message_log(filepath: Union[str, Path]) -> List[AgentMessage]:
    """Helper function to load AgentMessages from a JSONL file."""
    return MessageLog.load_jsonl(filepath).messages


def check_schema_compatibility(version: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate that an incoming schema version string is supported by the protocol engine.
    Returns (is_compatible, note_or_reason).
    """
    if not version:
        return True, "schema_version omitted; defaulted to v1.0"

    raw_v = str(version).strip().lower()
    if raw_v in SUPPORTED_SCHEMA_VERSIONS or raw_v.lstrip("v") in SUPPORTED_SCHEMA_VERSIONS:
        return True, f"schema_version '{version}' verified compatible"

    clean_v = raw_v.lstrip("v")
    if clean_v in {"1.0", "1.0.0", "1", "1.1"}:
        return True, f"schema_version '{version}' verified compatible"

    parts = clean_v.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        if major == 1:
            return True, f"higher minor schema_version '{version}' accepted in backward-compatible mode"
        return False, f"incompatible major schema_version '{version}' (expected v1.x)"
    except Exception:
        return False, f"unparseable or unsupported schema_version '{version}'"
