# NetCoop AI Network Diagnostic Engine

An intelligent multi-agent network fault diagnosis platform for automated incident triaging, root-cause analysis, and blast radius calculation across campus and enterprise network infrastructures.

---

## Architecture Overview

```
 Raw Telemetry JSON / Dict
           │
           ▼
┌─────────────────────────┐
│ Input Validator & Sanitizer │ (core/validator.py: UTF-8 BOM, unit normalization, schema coercion)
└────────────┬────────────┘
             │ RawTelemetryPayload + Ingestion Notes
             ▼
┌──────────────────────────────────────────────────────────┐
│               Domain Diagnostic Agents                   │
│  - TelemetryAgent      (RTT latency, loss, jitter, util) │
│  - InfrastructureAgent (CPU, RAM, queue drops, CRC/flaps)│
│  - TopologyAgent       (Redundancy-aware blast radius)   │
│  - WirelessAgent       (802.11 RSSI, SNR, retrans rate)  │
│  - ServiceAgent        (DNS latency, DNS fail, DHCP fail)│
└────────────────────────────┬─────────────────────────────┘
                             │ List[AgentFinding]
                             ▼
┌──────────────────────────────────────────────────────────┐
│                      Arbiter Agent                       │
│  (agents/arbiter_agent.py: Cross-domain corroboration,    │
│   canonical metric keys, conflict arbitration, confidence)│
└────────────────────────────┬─────────────────────────────┘
                             │ ArbitrationOutcome
                             ▼
┌──────────────────────────────────────────────────────────┐
│                     Reporter Agent                       │
│  (agents/reporter_agent.py: IncidentReport JSON, actions) │
└──────────────────────────────────────────────────────────┘
```

---

## Domain Agents

1. **TelemetryAgent (`agents/telemetry_agent.py`)**
   - Monitors transport quality: `rtt_latency_ms` (> 80.0ms), `packet_loss_pct` (> 2.0%), `jitter_ms` (> 25.0ms), `link_utilization_pct` (> 80.0%), `throughput_mbps`.
   - Filters metrics strictly by `device_id` and newest `timestamp`.

2. **InfrastructureAgent (`agents/infrastructure_agent.py`)**
   - Evaluates hardware health: `cpu_utilization_pct` (> 85.0%), `memory_utilization_pct` (> 90.0%), `egress_queue_drops` (> 0), `interface_crc_errors` (> 0).
   - Monitors link stability: `interface_errors` (> 10), `link_flaps` (> 3), `oper_status` (0 = down), `device_status` (0 = down).

3. **TopologyAgent (`agents/topology_agent.py`)**
   - Evaluates campus hierarchy adjacency graphs (`Edge AP -> Access Switch -> Distribution Router -> Core Gateway`).
   - Computes redundancy-aware blast radius: devices with alternative redundant uplinks (e.g. `core-gw-01` backup) are not falsely marked as isolated.
   - Deep-copies the topology graph per instance and supports loading custom topologies from payload metadata (`metadata["topology"]`).
   - Enforces case-insensitive device lookups across all queries and graph traversals.
   - Eliminates cycle bugs so the target start node never appears in its own downstream blast radius.
   - Correlates multi-device telemetry: when a target device shows symptoms and an upstream transit device exhibits an active fault (high CPU, CRC errors, link down, queue drops), the upstream device is reported as the probable root cause, listing the target device as affected.
   - Exposes case-insensitive metrics grouping helper via `BaseAgent.get_metrics_by_device(payload)`.

4. **WirelessAgent (`agents/wireless_agent.py`)**
   - Inspects RF characteristics: `rssi_dbm` (< -75 dBm is weak), `snr_db` (< 15 dB is poor), `retransmission_rate_pct` (> 10.0% is elevated).

5. **ServiceAgent (`agents/service_agent.py`)**
   - Evaluates critical network services: `dns_resolution_time_ms` (> 500ms), `dns_failure_rate_pct` (> 5.0%), `dhcp_discover_failures` (> 0).

---

## Confidence Scoring Methodology

The Arbiter derives its final diagnostic confidence from a mathematically rigorous, documented formulation:

$$\text{Confidence} = \text{Weighted Agent Confidence} \times \text{Corroboration Factor} \times \text{Data Completeness}$$

### 1. Weighted Agent Confidence
The confidence scores of domain agents providing supporting evidence are averaged according to domain authority weights:
- **InfrastructureAgent**: `1.2` (Hardware registers and physical counters)
- **WirelessAgent**: `1.1` (802.11 RF physical layer parameters)
- **TelemetryAgent**: `1.0` (Transport and QoS latency/loss metrics)
- **ServiceAgent**: `1.0` (Application layer service metrics)
- **TopologyAgent**: `0.8` (Graph topology and blast radius context)

$$\text{Weighted Agent Confidence} = \frac{\sum (c_i \times w_i)}{\sum w_i}$$

### 2. Corroboration Factor
Enforces cross-domain consensus across distinct agent domains:
- **$\ge 3$ distinct contributing agents**: `1.05` (Cross-domain corroboration bonus)
- **$2$ distinct contributing agents**: `1.00` (Standard two-domain corroboration)
- **$1$ contributing agent**: `0.50` (Uncorroborated single-agent penalty)
- **$0$ contributing agents**: `0.00`

> **Strict Corroboration Rule**: A diagnosis of `"diagnosed"` is never issued on a single metric or a single agent's finding. At least 2 corroborating evidence items from at least 2 distinct agents are required. Any uncorroborated single-agent finding is automatically degraded to `"inconclusive"` with confidence capped at $\le 0.50$.

### 3. Data Completeness
Reflects the ratio of observed relevant metrics to the expected baseline metrics:

$$\text{Data Completeness} = \min\left(1.0, 0.70 + 0.30 \times \frac{\min(\text{observed\_metrics}, \text{expected\_metrics})}{\max(\text{expected\_metrics}, 1)}\right)$$

---

## Diagnostic Rules & Conflict Arbitration

1. **Node Shutdown / Link Down**: Highest Layer 1/2 precedence. Explicit `device_status == 0` or `oper_status == 0` overrides downstream telemetry symptoms.
2. **Actionable CRC vs Weak Counters**: CRC/FCS counters $\le 5.0$ are treated as weak/incidental evidence and do not trigger physical degradation alarms without counter growth or transport packet drops.
3. **WAN Transit Delay vs Local Congestion**: High latency with normal utilization is only diagnosed as WAN transit delay if explicit infrastructure evidence confirms zero queue drops (`egress_queue_drops == 0`) and normal CPU (`cpu <= 85%`). Missing data is not evidence of absence.
4. **Weak Wi-Fi Interference**: Corroborates weak RSSI/SNR with high frame retransmissions.
5. **DNS/DHCP Service Outages**: Confirmed only when transport layer metrics (latency, loss, utilization) remain healthy.
6. **Dynamic Alternative Hypotheses**: `alternative_causes` are constructed dynamically from competing agent hypotheses rather than hardcoded canned lists.

---

## Installation & Setup

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Execution & CLI Usage

### Run Diagnostic Scenarios
```bash
# Link congestion scenario (High latency, 94% utilization, queue drops)
python main.py --scenario scenarios/link_congestion.json

# Normal operations baseline (Healthy metrics, edge AP)
python main.py --scenario scenarios/normal_ops.json

# Wi-Fi RF signal attenuation & frame retransmission storms
python main.py --scenario scenarios/weak_wifi.json

# Layer 2 interface flapping and packet errors
python main.py --scenario scenarios/interface_fault.json

# Application service outage (DNS timeouts & DHCP discover exhaustion)
python main.py --scenario scenarios/dns_dhcp_failure.json

# Cross-device upstream root cause fault propagation
python main.py --scenario scenarios/upstream_root_cause.json

# Layer 1/2 operational link down
python main.py --scenario scenarios/link_down.json

# Single-metric input resilience (never diagnosed, degraded to inconclusive)
python main.py --scenario scenarios/single_metric_insufficient.json

# Interoperability tests (renamed fields, dictionary metrics, unit in value)
python main.py --scenario scenarios/interop_renamed_fields.json
python main.py --scenario scenarios/interop_dict_metrics.json
python main.py --scenario scenarios/interop_unit_in_value.json
python main.py --scenario scenarios/malformed_data.json
```

### Save Incident Report to File
```bash
python main.py --scenario scenarios/link_congestion.json --output report.json
```

### Run Comprehensive Test Suite
```bash
pytest -v
```
