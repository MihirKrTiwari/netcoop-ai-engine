"""Reporting Agent (Member 4): packages the Arbiter verdict into the final
incident report (Section 6 JSON + Markdown ticket) and guarantees schema
compliance.

Required Section 6 fields: incident_id, status, suspected_root_cause,
confidence, affected_devices, supporting_evidence, alternative_causes,
recommended_actions, evidence_sources, limitations.
Extra fields: root_cause_key, generated_at, severity, summary,
input_validation_issues.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

VALID_STATUSES = {"diagnosed", "healthy", "insufficient_evidence"}
VALID_SEVERITIES = {"none", "low", "medium", "high", "critical", "unknown"}
REQUIRED_FIELDS = [
    "incident_id", "status", "suspected_root_cause", "confidence",
    "affected_devices", "supporting_evidence", "alternative_causes",
    "recommended_actions", "evidence_sources", "limitations",
]
STRING_LIST_FIELDS = ["affected_devices", "alternative_causes", "recommended_actions",
                      "evidence_sources", "limitations"]
LOW_CONFIDENCE = 0.3

LABELS: Dict[str, str] = {
    "congestion": "Likely link congestion causing egress queue drops (bufferbloat)",
    "hardware": "Likely hardware or link fault (interface CRC errors and link flapping)",
    "healthy": "No fault detected; all metrics are within baseline limits",
    "insufficient_evidence": "Insufficient evidence for a reliable diagnosis",
}

PLAYBOOK: Dict[str, List[str]] = {
    "congestion": [
        "Resize egress queue buffers on the saturated interface and enable AQM (fq_codel/CAKE) to curb bufferbloat.",
        "Apply QoS: prioritise latency-sensitive classes and rate-limit bulk traffic on the congested link.",
        "Identify top talkers (NetFlow/sFlow) and rebalance or throttle the heaviest flows.",
        "If utilization stays above ~85% at peak, plan a capacity upgrade or add a parallel/LAG link.",
    ],
    "hardware": [
        "Inspect and re-seat the cable and transceiver on the affected port; replace if CRC errors persist.",
        "Check for speed/duplex mismatch and review optical power levels (DOM) on both link ends.",
        "Move the link to a spare port or test with a known-good patch cable to isolate the fault.",
        "Open a hardware ticket for the interface/line card if errors continue after the physical fix.",
    ],
    "healthy": [
        "No action required; all metrics are within baseline limits.",
        "Continue routine monitoring and keep current alert thresholds.",
    ],
    "insufficient_evidence": [
        "Verify the telemetry collector and polling interval for the affected device; re-poll and re-run diagnosis.",
        "Check exporter/agent configuration for missing or mis-typed fields (see input validation issues).",
        "Escalate for manual inspection if telemetry remains incomplete.",
    ],
    "unclassified": [
        "Escalate to a network engineer for manual triage; the root cause did not match a known pattern.",
        "Collect interface counters, logs and a short packet capture on the affected device.",
    ],
}
SEVERITY = {"congestion": "medium", "hardware": "high", "healthy": "none",
            "insufficient_evidence": "unknown", "unclassified": "low"}


def _clamp(value: Any) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    if f != f:  # NaN
        return 0.0
    return max(0.0, min(1.0, f))


def _family(root_cause: Any) -> str:
    s = str(root_cause or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not s or any(k in s for k in ("insufficient", "unknown", "inconclusive")):
        return "insufficient_evidence"
    if any(k in s for k in ("healthy", "normal", "baseline", "no_fault")):
        return "healthy"
    if any(k in s for k in ("congest", "bufferbloat", "queue", "saturat")):
        return "congestion"
    if any(k in s for k in ("crc", "flap", "hardware", "cable", "optic", "physical")):
        return "hardware"
    return "unclassified"


def _str_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [f"{k}: {v}" for k, v in value.items()]
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for item in value:
            if isinstance(item, dict):
                out.append(str(item.get("name") or item.get("agent") or json.dumps(item, default=str)))
            else:
                out.append(str(item))
        return out
    return [str(value)]


def _evidence(value: Any) -> List[Dict[str, Any]]:
    """Normalise evidence into [{metric, value, interpretation}]."""
    items = value if isinstance(value, (list, tuple)) else ([] if value is None else [value])
    out: List[Dict[str, Any]] = []
    for it in items:
        if isinstance(it, dict):
            out.append({
                "metric": str(it.get("metric") or it.get("name") or "observation"),
                "value": it.get("value"),
                "interpretation": str(it.get("interpretation") or it.get("note") or ""),
            })
        else:
            s = str(it)
            m = re.match(r"^\s*([A-Za-z_][\w.]*)\s*[=:]\s*(-?\d+(?:\.\d+)?)\s*(.*)$", s)
            if m:
                out.append({"metric": m.group(1), "value": float(m.group(2)),
                            "interpretation": m.group(3).strip()})
            else:
                out.append({"metric": "observation", "value": None, "interpretation": s})
    return out


def _alternatives(value: Any) -> List[str]:
    items = value if isinstance(value, (list, tuple)) else ([] if value is None else [value])
    out: List[str] = []
    for it in items:
        if isinstance(it, dict):
            text = str(it.get("hypothesis") or it.get("cause") or it.get("root_cause") or "unspecified")
            if "confidence" in it:
                text += f" (confidence {_clamp(it['confidence']):.0%})"
            if it.get("reason"):
                text += f": {it['reason']}"
            out.append(text)
        else:
            out.append(str(it))
    return out


class ReporterAgent:
    """Turns an Arbiter verdict (+ optional validation result) into the final report."""

    def build_report(self, verdict: Optional[Dict[str, Any]] = None,
                     validation: Any = None) -> Dict[str, Any]:
        verdict = verdict if isinstance(verdict, dict) else {}
        issues = list(getattr(validation, "issues", []) or [])
        input_unusable = validation is not None and not getattr(validation, "usable", True)

        root_cause = "insufficient_evidence" if input_unusable else str(
            verdict.get("root_cause") or verdict.get("verdict") or "insufficient_evidence")
        family = _family(root_cause)
        confidence = 0.0 if input_unusable else _clamp(verdict.get("confidence"))
        status = {"healthy": "healthy", "insufficient_evidence": "insufficient_evidence"}.get(family, "diagnosed")

        limitations = _str_list(verdict.get("limitations"))
        if input_unusable:
            limitations.append("Input telemetry was too incomplete or corrupt to support a diagnosis.")
        elif issues:
            limitations.append("Some input fields were repaired or dropped during validation.")
        if status == "diagnosed" and confidence < LOW_CONFIDENCE:
            limitations.append("Low-confidence verdict; treat the root cause as a hypothesis.")
        if status == "diagnosed":
            limitations.append("Root cause requires further verification by a network engineer.")

        affected: List[str] = []
        if status == "diagnosed":
            affected = _str_list(verdict.get("affected_devices"))
            payload = getattr(validation, "payload", None)
            device = payload.get("device_id") if isinstance(payload, dict) else None
            if not affected and device and device != "unknown-device":
                affected = [device]

        if input_unusable:
            sources, evidence, alternatives = ["input_validator"], [], []
        else:
            sources = _str_list(verdict.get("contributing_agents"))
            evidence = _evidence(verdict.get("evidence") or verdict.get("supporting_evidence"))
            alternatives = _alternatives(verdict.get("alternatives") or verdict.get("alternative_hypotheses"))

        label = LABELS.get(family, f"Unclassified fault: {root_cause}")
        now = datetime.now(timezone.utc)
        return {
            "incident_id": f"INC-{now:%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4].upper()}",
            "status": status,
            "suspected_root_cause": label,
            "confidence": round(confidence, 4),
            "affected_devices": affected,
            "supporting_evidence": evidence,
            "alternative_causes": alternatives,
            "recommended_actions": list(PLAYBOOK[family]),
            "evidence_sources": sources,
            "limitations": limitations,
            "root_cause_key": root_cause,
            "generated_at": now.isoformat(timespec="seconds"),
            "severity": SEVERITY[family],
            "summary": self._summary(status, label, confidence),
            "input_validation_issues": issues,
        }

    @staticmethod
    def _summary(status: str, label: str, confidence: float) -> str:
        if status == "healthy":
            return "Network operating within baseline limits; no incident detected."
        if status == "insufficient_evidence":
            return "Insufficient valid evidence to determine a root cause."
        return f"{label} (confidence {confidence:.0%})."

    @staticmethod
    def to_json(report: Dict[str, Any], indent: int = 2) -> str:
        return json.dumps(report, indent=indent, default=str)

    @staticmethod
    def to_markdown(report: Dict[str, Any]) -> str:
        def bullets(items: List[str]) -> List[str]:
            return [f"- {i}" for i in items] or ["- none"]

        ev = [f"`{e.get('metric')}` = {e.get('value')}" + (f" ({e['interpretation']})" if e.get("interpretation") else "")
              for e in report.get("supporting_evidence", [])]
        lines = [
            f"# Incident {report.get('incident_id')}",
            f"**Status:** {report.get('status')} | **Severity:** {report.get('severity')} "
            f"| **Confidence:** {report.get('confidence', 0):.0%}",
            f"**Generated:** {report.get('generated_at')}",
            f"**Affected devices:** {', '.join(report.get('affected_devices', [])) or 'none identified'}",
            "", "## Summary", str(report.get("summary", "")),
            "", "## Suspected root cause", str(report.get("suspected_root_cause", "")),
            "", "## Supporting evidence",
        ] + bullets(ev)
        lines += ["", "## Alternative causes"] + bullets(report.get("alternative_causes", []))
        lines += ["", "## Recommended actions (priority order)"]
        lines += [f"{i}. {a}" for i, a in enumerate(report.get("recommended_actions", []), start=1)]
        lines += ["", "## Limitations"] + bullets(report.get("limitations", []))
        lines += ["", "**Evidence sources:** " + (", ".join(report.get("evidence_sources", [])) or "none")]
        if report.get("input_validation_issues"):
            lines += ["", "## Input validation issues"] + bullets(report["input_validation_issues"])
        return "\n".join(lines) + "\n"


def validate_report(report: Any) -> List[str]:
    """Return a list of schema violations (empty list == valid)."""
    if not isinstance(report, dict):
        return ["report must be an object"]
    errors = [f"missing field: {k}" for k in REQUIRED_FIELDS if k not in report]
    if errors:
        return errors
    if report["status"] not in VALID_STATUSES:
        errors.append(f"invalid status: {report['status']!r}")
    c = report["confidence"]
    if isinstance(c, bool) or not isinstance(c, (int, float)) or not 0.0 <= c <= 1.0:
        errors.append(f"confidence must be a number in [0.0, 1.0], got {c!r}")
    for k in ("incident_id", "suspected_root_cause"):
        if not isinstance(report[k], str) or not report[k]:
            errors.append(f"{k} must be a non-empty string")
    for k in STRING_LIST_FIELDS:
        v = report[k]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            errors.append(f"{k} must be a list of strings")
    if isinstance(report["recommended_actions"], list) and not report["recommended_actions"]:
        errors.append("recommended_actions must not be empty")
    ev = report["supporting_evidence"]
    if not isinstance(ev, list) or not all(
            isinstance(e, dict) and "metric" in e and "value" in e and isinstance(e.get("interpretation"), str)
            for e in ev):
        errors.append("supporting_evidence must be a list of {metric, value, interpretation}")
    if "severity" in report and report["severity"] not in VALID_SEVERITIES:
        errors.append(f"invalid severity: {report['severity']!r}")
    return errors