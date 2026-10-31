"""Tests for the NetCoop AI Telemetry & Performance Agent."""

import json

from agents.telemetry_agent import TelemetryPerformanceAgent


agent = TelemetryPerformanceAgent()


def test_high_latency_and_utilization_flag_possible_congestion():
    telemetry = {
        "incident_id": "INC-HIGH-001",
        "device_id": "SW-01",
        "metrics": {
            "rtt_latency": {"value": 0.28, "unit": "seconds"},
            "packet_loss": {"value": 0.08, "unit": "fraction"},
            "jitter": {"value": 35, "unit": "ms"},
            "link_utilization": {"value": 94, "unit": "percent"},
        },
    }

    result = agent.analyze(telemetry)

    assert result["health_state"] == "degraded"
    assert result["primary_hypothesis"] == "possible_network_congestion_or_bandwidth_saturation"
    assert result["normalized_metrics"]["rtt_latency_ms"] == 280.0
    assert result["normalized_metrics"]["packet_loss_pct"] == 8.0
    assert result["confidence"] >= 0.8


def test_normal_complete_telemetry_is_healthy():
    telemetry = {
        "incident_id": "INC-NORMAL-001",
        "device_id": "SW-02",
        "metrics": {
            "rtt_latency": {"value": 25, "unit": "ms"},
            "packet_loss": {"value": 0.2, "unit": "percent"},
            "jitter": {"value": 4, "unit": "ms"},
            "link_utilization": {"value": 35, "unit": "percent"},
        },
    }

    result = agent.analyze(telemetry)

    assert result["health_state"] == "healthy"
    assert result["primary_hypothesis"] is None
    assert result["confidence"] == 0.90


def test_missing_metrics_do_not_crash_and_are_reported():
    telemetry = {
        "incident_id": "INC-MISSING-001",
        "device_id": "AP-03",
        "metrics": {
            "rtt_latency": {"value": 45, "unit": "ms"},
            "jitter": {"value": 5, "unit": "ms"},
        },
    }

    result = agent.analyze(telemetry)

    assert result["health_state"] == "unknown"
    assert result["analysis_status"] == "partial"
    assert any("packet_loss_pct" in item for item in result["limitations"])
    assert any("link_utilization_pct" in item for item in result["limitations"])


def test_high_jitter_with_variable_rtt_samples_creates_hypothesis():
    telemetry = {
        "incident_id": "INC-JITTER-001",
        "device_id": "AP-04",
        "metrics": {
            "rtt_latency": {"value": 65, "unit": "ms"},
            "packet_loss": {"value": 0.2, "unit": "percent"},
            "jitter": {"value": 45, "unit": "ms"},
            "link_utilization": {"value": 50, "unit": "percent"},
            "rtt_samples": {"value": [20, 25, 110, 22, 115], "unit": "ms"},
        },
    }

    result = agent.analyze(telemetry)

    assert result["health_state"] == "degraded"
    assert result["primary_hypothesis"] == "possible_wireless_instability_or_queue_delay_variation"
    assert "rtt_stddev_ms" in result["normalized_metrics"]


def test_invalid_unit_is_reported_instead_of_silently_assumed():
    telemetry = {
        "incident_id": "INC-INVALID-001",
        "device_id": "SW-05",
        "metrics": {
            "rtt_latency": {"value": 0.2, "unit": "minutes"},
            "packet_loss": {"value": 0.1, "unit": "percent"},
            "jitter": {"value": 3, "unit": "ms"},
            "link_utilization": {"value": 45, "unit": "percent"},
        },
    }

    result = agent.analyze(telemetry)

    assert "rtt_latency_ms" not in result["normalized_metrics"]
    assert any("unsupported time unit" in item for item in result["limitations"])
    assert result["analysis_status"] == "partial"


def test_overflowing_measurements_are_reported_and_remain_json_safe():
    cases = [
        ("rtt_latency", {"value": 10**400, "unit": "ms"}, "rtt_latency_ms"),
        ("rtt_latency", {"value": 1e308, "unit": "seconds"}, "rtt_latency_ms"),
        ("throughput", {"value": 1e308, "unit": "gbps"}, "throughput_mbps"),
    ]

    for metric, measurement, normalized_key in cases:
        result = agent.analyze({
            "metrics": {
                "rtt_latency": {"value": 25, "unit": "ms"},
                "packet_loss": {"value": 0.2, "unit": "percent"},
                "jitter": {"value": 4, "unit": "ms"},
                "link_utilization": {"value": 35, "unit": "percent"},
                metric: measurement,
            },
        })

        assert normalized_key not in result["normalized_metrics"]
        assert any("Invalid " + normalized_key in item for item in result["limitations"])
        json.dumps(result, allow_nan=False)
