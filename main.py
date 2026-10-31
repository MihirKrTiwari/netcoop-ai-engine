"""
main.py
CLI entrypoint for NetCoop AI multi-agent network fault diagnosis engine.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from core.coordinator import NetCoopCoordinator


def build_parser() -> argparse.ArgumentParser:
    """
    Construct the command-line argument parser for NetCoop AI.
    """
    parser = argparse.ArgumentParser(
        prog="netcoop",
        description="NetCoop AI: Multi-Agent Network Fault Diagnosis Engine",
    )
    parser.add_argument(
        "--scenario",
        "-s",
        type=str,
        required=True,
        help="Path to the JSON scenario telemetry file to diagnose.",
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
        help="Output presentation format (default: json).",
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


def main() -> int:
    """
    Main execution workflow for CLI invocation.
    """
    parser = build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    scenario_path = Path(args.scenario)
    if not scenario_path.exists():
        sys.stderr.write(f"Error: Scenario file not found: {args.scenario}\n")
        return 1

    try:
        coordinator = NetCoopCoordinator()
        report = coordinator.run_from_file(str(scenario_path), incident_id=args.incident_id)

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
