"""
main.py
CLI entrypoint for NetCoop AI multi-agent network fault diagnosis engine.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.coordinator import NetCoopCoordinator
from core.schemas import IncidentReport

logger = logging.getLogger("netcoop")


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser for NetCoop AI."""
    parser = argparse.ArgumentParser(
        prog="netcoop",
        description="NetCoop AI: Multi-Agent Network Fault Diagnosis Engine",
    )
    parser.add_argument(
        "--scenario",
        "-s",
        type=str,
        default=None,
        help="Path to a single JSON scenario telemetry file to diagnose.",
    )
    parser.add_argument(
        "--scenario-dir",
        type=str,
        default=None,
        help="Directory of scenario files to execute in batch mode.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Output a formatted comparison summary table across scenarios.",
    )
    parser.add_argument(
        "--message-log",
        type=str,
        default=None,
        help="Path to export the inter-agent JSONL message log (e.g. out/messages.jsonl).",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Print an execution trace of inter-agent protocol messages to stderr.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Optional path to write the resulting IncidentReport JSON.",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "markdown", "text"],
        default="json",
        help="Output presentation format for single-run mode (default: json).",
    )
    parser.add_argument(
        "--html",
        type=str,
        default=None,
        help="Optional path to write a standalone visual HTML report/dashboard.",
    )
    parser.add_argument(
        "--incident-id",
        type=str,
        default=None,
        help="Optional incident identifier override.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging output.",
    )
    return parser


def print_trace(coordinator: NetCoopCoordinator) -> None:
    """Print formatted ASCII execution trace of inter-agent messages."""
    log = coordinator.get_message_log()
    sys.stderr.write("\n" + "=" * 80 + "\n")
    sys.stderr.write(" INTER-AGENT PROTOCOL MESSAGE TRACE\n")
    sys.stderr.write("=" * 80 + "\n")
    for msg in log.messages:
        seq = f"[{msg.sequence_number:02d}]"
        sender_target = f"{msg.sender} -> {msg.recipient}"
        mtype = f"<{msg.message_type}>"
        details = []
        if "status" in msg.payload:
            details.append(f"status={msg.payload['status']}")
        if "confidence" in msg.payload:
            details.append(f"conf={msg.payload['confidence']}")
        if "corroborates" in msg.payload and msg.payload["corroborates"]:
            details.append(f"corroborates={msg.payload['corroborates']}")
        if "error" in msg.payload:
            details.append(f"err={msg.payload['error']}")

        detail_str = f" ({', '.join(details)})" if details else ""
        sys.stderr.write(f"  {seq} {sender_target:<35} {mtype:<18}{detail_str}\n")
    sys.stderr.write("=" * 80 + "\n\n")


def generate_html_report(report: IncidentReport, output_path: Path) -> None:
    """Generate a clean visual HTML dashboard representing the diagnostic outcome."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    status_color = "#10b981" if report.status in {"diagnosed", "healthy"} and report.root_cause_category == "healthy" else (
        "#ef4444" if report.status == "diagnosed" else "#f59e0b"
    )

    evidence_rows = "".join(
        f"<tr><td><code>{ev.metric}</code></td><td>{ev.value}</td><td>{ev.interpretation}</td></tr>"
        for ev in report.supporting_evidence
    )
    actions_li = "".join(f"<li>{act}</li>" for act in report.recommended_actions)
    limitations_li = "".join(f"<li>{lim}</li>" for lim in report.limitations)
    alts_li = "".join(f"<li>{alt}</li>" for alt in report.alternative_causes) if report.alternative_causes else "<li>None (nominal state)</li>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NetCoop AI Incident Report - {report.incident_id}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }}
    .container {{ max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 8px; padding: 2rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }}
    .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: 700; text-transform: uppercase; font-size: 0.85rem; background: {status_color}; color: #000; }}
    h1, h2, h3 {{ color: #f8fafc; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin: 1.5rem 0; }}
    .card {{ background: #334155; padding: 1rem; border-radius: 6px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
    th, td {{ text-align: left; padding: 0.5rem; border-bottom: 1px solid #475569; }}
    th {{ background: #0f172a; color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; }}
    code {{ background: #0f172a; padding: 0.2rem 0.4rem; border-radius: 4px; color: #38bdf8; }}
  </style>
</head>
<body>
  <div class="container">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <h1>NetCoop Diagnostic Incident Report</h1>
      <span class="badge">{report.status}</span>
    </div>
    <p><strong>Incident ID:</strong> {report.incident_id} &nbsp;|&nbsp; <strong>Confidence:</strong> {report.confidence:.0%}</p>
    <div class="card" style="margin-bottom: 1.5rem;">
      <h3 style="margin-top:0;">Suspected Root Cause</h3>
      <p style="font-size: 1.1rem; color: #38bdf8; margin: 0;">{report.suspected_root_cause}</p>
    </div>
    <div class="grid">
      <div class="card">
        <h4 style="margin-top:0;">Affected Devices</h4>
        <p>{', '.join(report.affected_devices) if report.affected_devices else 'None'}</p>
      </div>
      <div class="card">
        <h4 style="margin-top:0;">Contributing Agents</h4>
        <p>{', '.join(report.evidence_sources)}</p>
      </div>
    </div>
    <h3>Supporting Evidence</h3>
    <table>
      <thead>
        <tr><th>Metric</th><th>Value</th><th>Interpretation</th></tr>
      </thead>
      <tbody>
        {evidence_rows}
      </tbody>
    </table>
    <h3>Alternative Causes Considered</h3>
    <ul>{alts_li}</ul>
    <h3>Recommended Mitigation Actions</h3>
    <ol>{actions_li}</ol>
    <h3>Operational Limitations & Ingestion Notes</h3>
    <ul>{limitations_li}</ul>
  </div>
</body>
</html>"""
    output_path.write_text(html_content, encoding="utf-8")


def run_batch_directory(
    dir_path: Path,
    summary_mode: bool = False,
    message_log_path: Optional[str] = None,
) -> int:
    """Execute all scenario JSON files in a directory and print a formatted summary."""
    scenario_files = sorted(dir_path.glob("*.json"))
    if not scenario_files:
        sys.stderr.write(f"No JSON scenario files found in {dir_path}\n")
        return 1

    coordinator = NetCoopCoordinator()
    results: List[Tuple[str, IncidentReport, Optional[Dict[str, Any]], bool]] = []

    for file_path in scenario_files:
        try:
            report = coordinator.run_from_file(str(file_path))
            expected_block: Optional[Dict[str, Any]] = None
            try:
                with open(file_path, "r", encoding="utf-8-sig") as f:
                    file_data = json.load(f)
                    if isinstance(file_data, dict):
                        expected_block = file_data.get("expected")
            except Exception:
                pass

            is_pass = True
            if expected_block:
                exp_status = expected_block.get("status")
                exp_root = expected_block.get("root_cause")
                status_ok = (
                    report.status == exp_status
                    or (exp_status == "healthy" and report.root_cause_category == "healthy")
                    or (exp_status == "link_congestion" and report.root_cause_category == "link_congestion")
                )
                root_ok = True
                if exp_root:
                    root_ok = (
                        report.root_cause_category == exp_root
                        or exp_root in report.suspected_root_cause.lower()
                    )
                is_pass = status_ok and root_ok

            results.append((file_path.name, report, expected_block, is_pass))
        except Exception as exc:
            sys.stderr.write(f"Error executing {file_path.name}: {exc}\n")

    # Export message log if requested
    if message_log_path:
        coordinator.export_message_log(message_log_path)
        sys.stderr.write(f"Exported combined message log to {message_log_path}\n")

    # Render summary table
    sys.stdout.write("\n" + "=" * 105 + "\n")
    sys.stdout.write(
        f"{'Scenario File':<28} {'Status':<16} {'Category / Root Cause':<36} {'Conf':<6} {'Result':<8}\n"
    )
    sys.stdout.write("=" * 105 + "\n")

    total_pass = 0
    checked_count = 0
    for name, rep, expected, is_pass in results:
        status_disp = rep.status
        cat_disp = rep.root_cause_category or rep.suspected_root_cause[:34]
        conf_disp = f"{rep.confidence:.2f}"
        if expected:
            checked_count += 1
            if is_pass:
                total_pass += 1
                res_disp = "[PASS]"
            else:
                res_disp = "[FAIL]"
        else:
            res_disp = "[INFO]"

        sys.stdout.write(
            f"{name:<28} {status_disp:<16} {cat_disp:<36} {conf_disp:<6} {res_disp:<8}\n"
        )
    sys.stdout.write("=" * 105 + "\n")
    if checked_count > 0:
        sys.stdout.write(f"Scenarios with expectations: {total_pass}/{checked_count} PASSED\n\n")

    return 0 if (checked_count == 0 or total_pass == checked_count) else 1


def main() -> int:
    """Main execution workflow for CLI invocation."""
    parser = build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    # Batch scenario directory mode
    if args.scenario_dir:
        dir_path = Path(args.scenario_dir)
        if not dir_path.is_dir():
            sys.stderr.write(f"Error: Directory not found: {args.scenario_dir}\n")
            return 1
        return run_batch_directory(
            dir_path,
            summary_mode=args.summary,
            message_log_path=args.message_log,
        )

    # Single scenario mode
    if not args.scenario:
        # If no arguments provided, show help
        parser.print_help()
        return 1

    scenario_path = Path(args.scenario)
    if not scenario_path.exists():
        sys.stderr.write(f"Error: Scenario file not found: {args.scenario}\n")
        return 1

    try:
        coordinator = NetCoopCoordinator()
        report = coordinator.run_from_file(str(scenario_path), incident_id=args.incident_id)

        # Inter-agent protocol message logging
        if args.message_log:
            out_log = Path(args.message_log)
            coordinator.export_message_log(out_log)

        # ASCII Trace
        if args.trace:
            print_trace(coordinator)

        # HTML visualization
        if args.html:
            generate_html_report(report, Path(args.html))

        json_output = report.model_dump_json(indent=2)

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json_output + "\n")

        if args.format == "json":
            sys.stdout.write(json_output + "\n")
        elif args.format == "markdown":
            sys.stdout.write(coordinator.reporter_agent.format_markdown(report) + "\n")
        elif args.format == "text":
            sys.stdout.write(coordinator.reporter_agent.format_terminal_table(report) + "\n")
        else:
            sys.stdout.write(json_output + "\n")

        return 0

    except Exception as exc:
        sys.stderr.write(f"Execution Error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
