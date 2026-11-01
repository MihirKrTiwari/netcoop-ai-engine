#!/usr/bin/env python3
"""
scripts/generate_scenarios.py
Deterministic synthetic network telemetry scenario generator for NetCoop AI.
Utilizes generate_telemetry() to produce calibrated synthetic network telemetry cases.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import random
from typing import Any, Dict, List


def generate_telemetry(fault_type: str = "normal") -> Dict[str, Any]:
    """
    Generate synthetic network telemetry based on specified fault type.
    Fault types:
      - 'normal': Nominal baseline performance metrics (Healthy)
      - 'latency_spike': Buffer queue saturation and RTT delay (Warning)
      - 'hardware_failure': Core link saturation, packet drops, interface errors (Critical)
      - 'weak_wifi': Wireless 802.11 RF signal attenuation (Warning)
      - 'dns_failure': Core DNS/DHCP resolver outage (Critical)
    """
    data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "device_id": f"SW_CAMPUS_{random.randint(1, 10)}",
        "metrics": {}
    }

    if fault_type == "latency_spike":
        data["metrics"] = {
            "cpu_utilization_pct": round(random.uniform(40, 70), 2),
            "link_utilization_pct": round(random.uniform(60, 85), 2),
            "packet_loss_pct": round(random.uniform(0.1, 1.5), 2),
            "latency_ms": round(random.uniform(150, 400), 2),  # Spike
            "jitter_ms": round(random.uniform(30, 80), 2),
            "queue_drops": random.randint(0, 50)
        }
        data["status"] = "Warning"
    elif fault_type == "hardware_failure":
        data["metrics"] = {
            "cpu_utilization_pct": 99.9,
            "link_utilization_pct": 100.0,
            "packet_loss_pct": round(random.uniform(15, 30), 2),
            "latency_ms": round(random.uniform(500, 1000), 2),
            "queue_drops": random.randint(5000, 15000),
            "interface_errors": random.randint(100, 500)
        }
        data["status"] = "Critical"
    elif fault_type == "weak_wifi":
        data["metrics"] = {
            "rssi_dbm": round(random.uniform(-88.0, -80.0), 1),
            "snr_db": round(random.uniform(6.0, 12.0), 1),
            "retransmission_rate_pct": round(random.uniform(18.0, 35.0), 1),
            "packet_loss_pct": round(random.uniform(6.0, 12.0), 1),
        }
        data["status"] = "Warning"
    elif fault_type == "dns_failure":
        data["metrics"] = {
            "dns_resolution_time_ms": round(random.uniform(900.0, 1800.0), 1),
            "dns_failure_rate_pct": round(random.uniform(25.0, 45.0), 1),
            "latency_ms": round(random.uniform(3.0, 8.0), 1),
            "queue_drops": 0,
        }
        data["status"] = "Critical"
    else:
        data["metrics"] = {
            "cpu_utilization_pct": round(random.uniform(10, 35), 2),
            "link_utilization_pct": round(random.uniform(20, 50), 2),
            "packet_loss_pct": 0.0,
            "latency_ms": round(random.uniform(5, 20), 2),
            "jitter_ms": round(random.uniform(1, 5), 2),
            "queue_drops": 0
        }
        data["status"] = "Healthy"

    return data


def generate_scenarios(seed: int = 42, output_dir: Path = Path("scenarios/generated")) -> List[Path]:
    """Generate deterministic scenario payloads using the synthetic telemetry generator."""
    random.seed(seed)
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_files: List[Path] = []

    # Map fault types to standard scenario targets and root cause expectations
    scenario_configs = [
        ("normal", "gen_healthy.json", "healthy", "diagnosed"),
        ("latency_spike", "gen_congestion.json", "link_congestion", "diagnosed"),
        ("hardware_failure", "gen_crc_fault.json", "hardware_link_flap", "diagnosed"),
        ("weak_wifi", "gen_weak_wifi.json", "weak_wifi", "diagnosed"),
        ("dns_failure", "gen_dns_failure.json", "dns_dhcp_failure", "diagnosed"),
    ]

    for fault_type, filename, expected_root, default_status in scenario_configs:
        payload = generate_telemetry(fault_type)
        payload["scenario_id"] = f"{filename.replace('.json', '')}_{seed}"
        
        # Expected status calibration
        exp_status = default_status
        exp_root = expected_root
        if fault_type == "latency_spike" and payload["metrics"].get("queue_drops", 0) == 0:
            exp_status = "inconclusive"
            exp_root = "inconclusive"

        payload["expected"] = {"status": exp_status, "root_cause": exp_root}
        payload["metadata"] = {"generator_seed": seed, "fault_type": fault_type}
        
        file_path = output_dir / filename
        file_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        generated_files.append(file_path)

    return generated_files


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic Synthetic Telemetry Scenario Generator")
    parser.add_argument("--seed", type=int, default=42, help="Fixed random seed (default: 42)")
    parser.add_argument("--out-dir", type=str, default="scenarios/generated", help="Output directory")
    parser.add_argument("--fault-type", type=str, default=None, choices=["normal", "latency_spike", "hardware_failure", "weak_wifi", "dns_failure"], help="Optional single scenario generator mode")
    args = parser.parse_args()

    if args.fault_type:
        sample = generate_telemetry(args.fault_type)
        print(json.dumps(sample, indent=2))
        return

    files = generate_scenarios(seed=args.seed, output_dir=Path(args.out_dir))
    print(f"Generated {len(files)} deterministic scenarios in {args.out_dir} with seed={args.seed}:")
    for f in files:
        print(f"  - {f}")


if __name__ == "__main__":
    main()
