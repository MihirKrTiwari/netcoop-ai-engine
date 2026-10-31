#!/usr/bin/env python3
"""
scripts/generate_scenarios.py
Deterministic synthetic telemetry scenario generator for NetCoop AI.
Uses a fixed random seed (default 42) to ensure benchmark repeatability.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
from typing import Any, Dict, List


def generate_scenarios(seed: int = 42, output_dir: Path = Path("scenarios/generated")) -> List[Path]:
    """Generate deterministic scenario payloads using a fixed random seed."""
    random.seed(seed)
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_files: List[Path] = []

    # 1. Healthy Baseline Scenario
    healthy_scenario = {
        "scenario_id": f"gen_healthy_{seed}",
        "schema_version": "1.0",
        "timestamp": "2026-10-31T12:00:00Z",
        "target_device": "core-sw-01",
        "metadata": {"generator_seed": seed, "network_role": "datacenter_core"},
        "metrics": [
            {"metric_name": "rtt_latency_ms", "value": round(random.uniform(5.0, 15.0), 2), "unit": "ms"},
            {"metric_name": "packet_loss_pct", "value": round(random.uniform(0.0, 0.2), 2), "unit": "%"},
            {"metric_name": "jitter_ms", "value": round(random.uniform(1.0, 3.0), 2), "unit": "ms"},
            {"metric_name": "link_utilization_pct", "value": round(random.uniform(20.0, 45.0), 1), "unit": "%"},
            {"metric_name": "cpu_utilization_pct", "value": round(random.uniform(25.0, 50.0), 1), "unit": "%"},
            {"metric_name": "memory_utilization_pct", "value": round(random.uniform(40.0, 60.0), 1), "unit": "%"},
            {"metric_name": "egress_queue_drops", "value": 0, "unit": "count"},
            {"metric_name": "interface_crc_errors", "value": 0, "unit": "count"},
        ],
        "expected": {"status": "diagnosed", "root_cause": "healthy"}
    }
    p1 = output_dir / "gen_healthy.json"
    p1.write_text(json.dumps(healthy_scenario, indent=2), encoding="utf-8")
    generated_files.append(p1)

    # 2. Link Congestion Scenario
    congestion_scenario = {
        "scenario_id": f"gen_congestion_{seed}",
        "schema_version": "1.0",
        "timestamp": "2026-10-31T12:05:00Z",
        "target_device": "dist-sw-01",
        "metadata": {"generator_seed": seed, "network_role": "distribution"},
        "metrics": [
            {"metric_name": "rtt_latency_ms", "value": round(random.uniform(120.0, 180.0), 2), "unit": "ms"},
            {"metric_name": "packet_loss_pct", "value": round(random.uniform(3.0, 6.0), 2), "unit": "%"},
            {"metric_name": "link_utilization_pct", "value": round(random.uniform(90.0, 98.0), 1), "unit": "%"},
            {"metric_name": "egress_queue_drops", "value": random.randint(300, 1200), "unit": "count"},
            {"metric_name": "interface_crc_errors", "value": 0, "unit": "count"},
            {"metric_name": "cpu_utilization_pct", "value": round(random.uniform(30.0, 50.0), 1), "unit": "%"},
        ],
        "expected": {"status": "diagnosed", "root_cause": "link_congestion"}
    }
    p2 = output_dir / "gen_congestion.json"
    p2.write_text(json.dumps(congestion_scenario, indent=2), encoding="utf-8")
    generated_files.append(p2)

    # 3. Physical Hardware Cable / CRC Degradation
    crc_scenario = {
        "scenario_id": f"gen_crc_fault_{seed}",
        "schema_version": "1.0",
        "timestamp": "2026-10-31T12:10:00Z",
        "target_device": "edge-sw-02",
        "metadata": {"generator_seed": seed, "network_role": "access"},
        "metrics": [
            {"metric_name": "rtt_latency_ms", "value": round(random.uniform(40.0, 80.0), 2), "unit": "ms"},
            {"metric_name": "packet_loss_pct", "value": round(random.uniform(5.0, 10.0), 2), "unit": "%"},
            {"metric_name": "interface_crc_errors", "value": random.randint(50, 250), "unit": "count"},
            {"metric_name": "link_flaps", "value": random.randint(4, 12), "unit": "count"},
            {"metric_name": "egress_queue_drops", "value": 0, "unit": "count"},
        ],
        "expected": {"status": "diagnosed", "root_cause": "hardware_link_flap"}
    }
    p3 = output_dir / "gen_crc_fault.json"
    p3.write_text(json.dumps(crc_scenario, indent=2), encoding="utf-8")
    generated_files.append(p3)

    # 4. Weak Wi-Fi RF Attenuation Scenario
    wifi_scenario = {
        "scenario_id": f"gen_weak_wifi_{seed}",
        "schema_version": "1.0",
        "timestamp": "2026-10-31T12:15:00Z",
        "target_device": "hostel-ap-03",
        "metadata": {"generator_seed": seed, "network_role": "wireless_ap"},
        "metrics": [
            {"metric_name": "rssi_dbm", "value": round(random.uniform(-88.0, -80.0), 1), "unit": "dBm"},
            {"metric_name": "snr_db", "value": round(random.uniform(6.0, 12.0), 1), "unit": "dB"},
            {"metric_name": "retransmission_rate_pct", "value": round(random.uniform(18.0, 35.0), 1), "unit": "%"},
            {"metric_name": "packet_loss_pct", "value": round(random.uniform(6.0, 12.0), 1), "unit": "%"},
        ],
        "expected": {"status": "diagnosed", "root_cause": "weak_wifi"}
    }
    p4 = output_dir / "gen_weak_wifi.json"
    p4.write_text(json.dumps(wifi_scenario, indent=2), encoding="utf-8")
    generated_files.append(p4)

    # 5. Service Layer DNS Failure Scenario
    dns_scenario = {
        "scenario_id": f"gen_dns_failure_{seed}",
        "schema_version": "1.0",
        "timestamp": "2026-10-31T12:20:00Z",
        "target_device": "dns-resolver-01",
        "metadata": {"generator_seed": seed, "network_role": "service_host"},
        "metrics": [
            {"metric_name": "dns_resolution_time_ms", "value": round(random.uniform(900.0, 1800.0), 1), "unit": "ms"},
            {"metric_name": "dns_failure_rate_pct", "value": round(random.uniform(25.0, 45.0), 1), "unit": "%"},
            {"metric_name": "rtt_latency_ms", "value": round(random.uniform(3.0, 8.0), 1), "unit": "ms"},
            {"metric_name": "egress_queue_drops", "value": 0, "unit": "count"},
        ],
        "expected": {"status": "diagnosed", "root_cause": "dns_dhcp_failure"}
    }
    p5 = output_dir / "gen_dns_failure.json"
    p5.write_text(json.dumps(dns_scenario, indent=2), encoding="utf-8")
    generated_files.append(p5)

    return generated_files


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic Telemetry Scenario Generator")
    parser.add_argument("--seed", type=int, default=42, help="Fixed random seed (default: 42)")
    parser.add_argument("--out-dir", type=str, default="scenarios/generated", help="Output directory")
    args = parser.parse_args()

    files = generate_scenarios(seed=args.seed, output_dir=Path(args.out_dir))
    print(f"Generated {len(files)} deterministic scenarios in {args.out_dir} with seed={args.seed}:")
    for f in files:
        print(f"  - {f}")


if __name__ == "__main__":
    main()
