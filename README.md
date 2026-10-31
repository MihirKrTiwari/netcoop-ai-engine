# NetCoop AI Network Diagnostic Engine

An intelligent, deterministic multi-agent network fault diagnosis platform designed for automated incident triaging, root-cause analysis, blast radius calculation, and cross-domain peer corroboration across enterprise and campus network infrastructures.

---

## Architecture & Protocol Flow

```
                      Raw Telemetry (JSON / Dict / File)
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Input Validator/Sanitizer │ (core/validator.py)
                        │  - UTF-8 BOM stripping    │
                        │  - Alias canonicalization │
                        │  - Unit conversion        │
                        │  - Schema version check   │
                        └─────────────┬─────────────┘
                                      │
                         RawTelemetryPayload + Ingestion Notes
                                      │
                                      ▼
                      ┌───────────────────────────────┐
                      │    Coordinator Event Loop     │ (core/coordinator.py)
                      │    MessageLog (JSONL Trace)   │
                      └───────┬───────────────┬───────┘
                              │               │
           Dispatch Telemetry │               │
                              ▼               ▼
      ┌──────────────────────────────────────────────────────────────┐
      │                   Domain Diagnostic Agents                   │
      │  ┌────────────────────┐            ┌──────────────────────┐  │
      │  │   TelemetryAgent   │            │ InfrastructureAgent  │  │
      │  │ (latency, loss,    │            │ (CPU, RAM, drops,    │  │
      │  │  jitter, util, bw) │            │  CRC, flaps, status) │  │
      │  └─────────┬──────────┘            └──────────┬───────────┘  │
      │            │                                  │              │
      │  ┌─────────┴──────────┐            ┌──────────┴───────────┐  │
      │  │    TopologyAgent   │            │    WirelessAgent     │  │
      │  │ (blast radius, SPDF│            │ (802.11 RSSI, SNR,   │  │
      │  │  upstream faults)  │            │  retransmissions)    │  │
      │  └─────────┬──────────┘            └──────────┬───────────┘  │
      │            │                       ┌──────────┴───────────┐  │
      │            │                       │     ServiceAgent     │  │
      │            │                       │ (DNS time/fail, DHCP)│  │
      │            │                       └──────────┬───────────┘  │
      └────────────┼──────────────────────────────────┼──────────────┘
                   │                                  │
                   │ Phase 1 Findings                 │
                   ▼                                  ▼
      ┌──────────────────────────────────────────────────────────────┐
      │             Phase 2: Peer-Review Cross-Assessment            │
      │  Agents inspect peer findings, emit cross-domain citations,  │
      │  and attach corroborating evidence tags.                     │
      └──────────────────────────────┬───────────────────────────────┘
                                     │
                        List[AgentFinding] + Reviews
                                     │
                                     ▼
                      ┌─────────────────────────────┐
                      │        Arbiter Agent        │ (agents/arbiter_agent.py)
                      │  - Two-agent corroboration  │
                      │  - Conflict resolution rules│
                      │  - Mathematical confidence  │
                      └──────────────┬──────────────┘
                                     │ ArbitrationOutcome
                                     ▼
                      ┌─────────────────────────────┐
                      │       Reporter Agent        │ (agents/reporter_agent.py)
                      │  - Standard Challenge Schema│
                      │  - Mitigations & Actions    │
                      │  - Deduplicated Limitations │
                      └──────────────┬──────────────┘
                                     │
                                     ▼
                         IncidentReport (JSON / HTML)
```

---

## Inter-Agent Protocol Specification

Diagnostic agents interact via structured envelopes (`core/protocol.py: AgentMessage`) tracked in an append-only, thread-safe `MessageLog`.

### Message Envelope Structure

```json
{
  "message_id": "msg-6792d4595f90",
  "incident_id": "INC-7F7FDE62",
  "correlation_id": "INC-7F7FDE62",
  "schema_version": "1.0",
  "message_type": "peer_review",
  "sender": "TelemetryAgent",
  "recipient": "coordinator",
  "sequence_number": 7,
  "created_at": "2026-10-31T14:09:39.847+00:00",
  "timestamp": "2026-10-31T14:09:39.847+00:00",
  "payload": {
    "agent": "TelemetryAgent",
    "corroborates": ["InfrastructureAgent:queue_drops"],
    "peer_assessments": [
      "Observed queuing delay and packet loss corroborate egress buffer drops (160 drops) reported by InfrastructureAgent."
    ]
  }
}
```

### Protocol Fields

| Field | Type | Description |
|---|---|---|
| `message_id` | `str` | Globally unique message UUID prefixed with `msg-`. |
| `incident_id` | `str` | Correlates all events belonging to a diagnostic investigation session. |
| `schema_version` | `str` | Protocol version (`1.0`). Validated via `check_schema_compatibility()`. |
| `message_type` | `str` | Message intent: `telemetry_ingest`, `agent_finding`, `peer_review`, `arbiter_request`, `arbiter_verdict`, `error`. |
| `sender` | `str` | Component origin (`coordinator`, `TelemetryAgent`, etc.). |
| `recipient` | `str` | Intended destination component. |
| `sequence_number` | `int` | Monotonically increasing sequence number ensuring causal ordering. |
| `created_at` | `str` | ISO-8601 UTC timestamp with millisecond precision. |
| `payload` | `dict` | Structured data payload containing metrics, findings, or peer assessments. |

### Schema Version Negotiation Rules
1. **Compatible Minor Versions**: Schemas sharing major version `1.x` (`1.0`, `1.1`, `1.0.0`, `netcoop-v1`) are accepted in backward-compatible mode.
2. **Incompatible Major Versions**: Versions outside `1.x` (e.g. `2.0`, `0.9`) are safely quarantined; the pipeline records an ingestion note in `IncidentReport.limitations` and proceeds in graceful fallback mode without crashing.
3. **Missing Version**: Defaulted to `v1.0`.

---

## Canonical Metrics & Threshold Reference

All incoming metrics are mapped to canonical identifiers before agent analysis:

| Canonical Metric Name | Canonical Key | Default Unit | Supported Aliases | Anomaly Threshold | Responsible Agent |
|---|---|---|---|---|---|
| `rtt_latency_ms` | `latency` | `ms` | `rtt_ms`, `rtt`, `latency_ms`, `rtt_s` (converted) | > 80.0 ms | TelemetryAgent |
| `packet_loss_pct` | `packet_loss` | `%` | `loss_pct`, `packet_loss`, `packet_loss_ratio` | > 2.0 % | TelemetryAgent |
| `jitter_ms` | `jitter` | `ms` | `jitter`, `delay_jitter_ms` | > 25.0 ms | TelemetryAgent |
| `link_utilization_pct` | `utilization` | `%` | `link_utilization`, `utilization_pct`, `util` | > 80.0 % | TelemetryAgent |
| `throughput_mbps` | `throughput` | `Mbps` | `throughput`, `bandwidth_mbps`, `throughput_gbps` | < 100.0 Mbps | TelemetryAgent |
| `cpu_utilization_pct` | `cpu` | `%` | `cpu`, `cpu_pct`, `cpu_utilization` | > 85.0 % | InfrastructureAgent |
| `memory_utilization_pct` | `memory` | `%` | `memory`, `ram_pct`, `system_ram_pct`, `memory_pct` | > 90.0 % | InfrastructureAgent |
| `egress_queue_drops` | `queue_drops` | `count` | `queue_drops`, `egress_drops`, `tx_drops` | > 0 drops | InfrastructureAgent |
| `interface_crc_errors` | `crc_errors` | `count` | `crc_errors`, `fcs_errors`, `interface_fcs_errors` | > 5 count | InfrastructureAgent |
| `interface_errors` | `interface_errors` | `count` | `if_errors`, `port_errors`, `rx_errors` | > 10 count | InfrastructureAgent |
| `link_flaps` | `link_flaps` | `count` | `carrier_transitions`, `flaps`, `interface_flaps` | > 3 count | InfrastructureAgent |
| `oper_status` | `oper_status` | `state` | `link_state`, `if_oper_status`, `interface_state` | == 0 (Down) | InfrastructureAgent |
| `device_status` | `device_status` | `state` | `node_status`, `system_health`, `device_state` | == 0 (Down) | InfrastructureAgent |
| `rssi_dbm` | `rssi` | `dBm` | `rssi`, `signal_strength_dbm` | < -75.0 dBm | WirelessAgent |
| `snr_db` | `snr` | `dB` | `snr`, `signal_to_noise_ratio` | < 15.0 dB | WirelessAgent |
| `retransmission_rate_pct`| `retransmission_rate` | `%` | `retransmission_rate`, `retransmissions_pct` | > 10.0 % | WirelessAgent |
| `dns_resolution_time_ms`| `dns_time` | `ms` | `dns_latency_ms`, `dns_resolution_time` | > 500.0 ms | ServiceAgent |
| `dns_failure_rate_pct` | `dns_failure_rate` | `%` | `dns_failure_rate`, `dns_error_rate_pct` | > 5.0 % | ServiceAgent |
| `dhcp_discover_failures`| `dhcp_failures` | `count` | `dhcp_failures`, `dhcp_timeouts` | > 0 count | ServiceAgent |
| `downstream_blast_radius`| `downstream_blast_radius` | `count` | `blast_radius`, `isolated_devices` | > 0 devices | TopologyAgent |

---

## Status Semantics

The engine outputs one of four deterministic diagnostic statuses:

- `diagnosed`: Corroborated fault condition confirmed by $\ge 2$ independent agents with matching evidence.
- `healthy`: All observed metrics fall strictly within nominal bounds, with required core telemetry present.
- `inconclusive`: Anomaly detected by a single domain agent without corroboration, or contradictory cross-domain signals. Confidence is capped at $\le 0.50$.
- `insufficient_evidence`: Critical baseline telemetry is missing, or input data was corrupt/unusable. Exact root cause is never claimed. Confidence is set to $0.00$.

---

## Confidence Scoring Formula

The Arbiter derives its final diagnostic confidence from a mathematically scored formulation:

$$\text{Confidence} = \text{Weighted Agent Confidence} \times \text{Corroboration Factor} \times \text{Data Completeness}$$

### 1. Weighted Agent Confidence
Domain agents providing supporting evidence are averaged according to domain authority weights:
- **InfrastructureAgent**: `1.2` (Hardware registers and physical counters)
- **WirelessAgent**: `1.1` (802.11 RF physical layer parameters)
- **TelemetryAgent**: `1.0` (Transport and QoS latency/loss metrics)
- **ServiceAgent**: `1.0` (Application layer service metrics)
- **TopologyAgent**: `0.8` (Graph topology and blast radius context)

$$\text{Weighted Confidence} = \frac{\sum (c_i \times w_i)}{\sum w_i}$$

### 2. Corroboration Factor
Enforces cross-domain consensus across distinct agent domains:
- **$\ge 3$ distinct contributing agents**: `1.05` (Cross-domain corroboration bonus)
- **$2$ distinct contributing agents**: `1.00` (Standard two-domain corroboration)
- **$1$ contributing agent**: `0.50` (Uncorroborated single-agent penalty)
- **$0$ contributing agents**: `0.00`

> **Safety Invariant**: A diagnosis of `"diagnosed"` is NEVER issued on a single metric or a single agent's finding. Uncorroborated single-agent findings are automatically degraded to `"inconclusive"` with confidence capped at $\le 0.50$.

### 3. Data Completeness
Reflects the ratio of observed relevant metrics to the expected baseline metrics:

$$\text{Data Completeness} = \min\left(1.0, 0.70 + 0.30 \times \frac{\min(\text{observed\_metrics}, \text{expected\_metrics})}{\max(\text{expected\_metrics}, 1)}\right)$$

---

## Ingestion & Error Handling Resilience

NetCoop AI is hardened against real-world data corruption:
- **Dirty Data Coercion**: Coerces stringified numbers (`"4.2%"`, `"12 ms"`, `"0.150s"`), strips units embedded inside values, and logs conversions in `limitations`.
- **Flat & Nested Ingestion**: Transparently parses dictionary metrics (`{"rtt_ms": 10}`), list metrics, and renamed keys (`target` -> `target_device`).
- **Timestamp Unification**: `core/timeutils.py` chronologically parses ISO-8601 (naive or timezone-aware with Z or `+05:30` offsets) and epoch seconds/milliseconds.
- **Corrupt Payload Isolation**: All-corrupt or unparseable input files degrade gracefully to `insufficient_evidence` with clear notes and zero tracebacks.
- **Agent Fault Isolation**: Each agent analysis is wrapped in `try/except`. If an agent throws an unhandled exception, it emits an `insufficient_evidence` finding and the remaining agents successfully complete diagnosis.

---

## CLI Usage & Demo Commands

### 1. Batch Scenario Execution & Summary Table
Execute all scenarios in batch mode and verify results against expected blocks:
```bash
python main.py --scenario-dir scenarios --summary
```
Output:
```
=========================================================================================================
Scenario File                Status           Category / Root Cause                Conf   Result  
=========================================================================================================
m4_A_healthy.json            diagnosed        healthy                              0.92   [PASS]  
m4_B_congestion.json         diagnosed        link_congestion                      0.95   [PASS]  
m4_C_link_flap.json          diagnosed        hardware_link_flap                   0.94   [PASS]  
m4_D_dirty_data.json         diagnosed        link_congestion                      0.95   [PASS]  
m4_E_corrupt.json            insufficient_evidence insufficient_evidence                0.00   [PASS]  
link_congestion.json         diagnosed        link_congestion                      0.95   [INFO]  
normal_ops.json              diagnosed        healthy                              0.92   [INFO]  
...
=========================================================================================================
Scenarios with expectations: 5/5 PASSED
```

### 2. Export Inter-Agent Protocol Message Log (JSONL)
```bash
python main.py --scenario scenarios/link_congestion.json --message-log out/messages.jsonl
```

### 3. Live Protocol Message Trace
```bash
python main.py --scenario scenarios/link_congestion.json --trace
```

### 4. Visual HTML Dashboard Report
Generate a visual standalone HTML report:
```bash
python main.py --scenario scenarios/link_congestion.json --html out/dashboard.html
```

### 5. Generate Deterministic Synthetic Scenarios
Generate benchmark test scenarios using a fixed random seed:
```bash
python scripts/generate_scenarios.py --seed 42 --out-dir scenarios/generated
python main.py --scenario-dir scenarios/generated --summary
```

---

## Running Test Suite

```bash
# Run all unit, integration, protocol, and end-to-end tests
pytest -v

# Run Member 4 scenario tests specifically
pytest tests/test_m4_e2e.py -v

# Run protocol envelope and message log tests
pytest tests/test_protocol.py -v
```
