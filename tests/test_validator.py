"""
tests/test_validator.py
Comprehensive test suite for NetCoop AI telemetry validation and sanitization.
"""

import logging
import pytest

from core.schemas import RawTelemetryPayload, TelemetryMetric
from core.validator import validate_and_sanitize_payload


class TestValidPayloadIngestion:
    """
    Test suite validating clean, well-formed telemetry payload ingestion.
    """

    def test_valid_full_payload_ingestion(self) -> None:
        raw_input = {
            "scenario_id": "link_congestion_001",
            "target_device": "router-core-alpha",
            "metadata": {
                "environment": "production",
                "datacenter": "us-east-1",
                "firmware_version": "17.3.4",
            },
            "metrics": [
                {
                    "metric_name": "rtt_latency",
                    "value": 14.5,
                    "unit": "ms",
                    "timestamp": "2026-10-31T14:00:00Z",
                    "device_id": "router-core-alpha",
                },
                {
                    "metric_name": "interface_utilization",
                    "value": 87.2,
                    "unit": "%",
                    "timestamp": "2026-10-31T14:00:05Z",
                    "device_id": "router-core-alpha",
                },
                {
                    "metric_name": "egress_throughput",
                    "value": 940.0,
                    "unit": "mbps",
                    "timestamp": "2026-10-31T14:00:10Z",
                    "device_id": "router-core-beta",
                },
            ],
        }

        payload: RawTelemetryPayload = validate_and_sanitize_payload(raw_input)

        assert isinstance(payload, RawTelemetryPayload)
        assert payload.scenario_id == "link_congestion_001"
        assert payload.target_device == "router-core-alpha"
        assert payload.metadata["environment"] == "production"
        assert payload.metadata["datacenter"] == "us-east-1"
        assert len(payload.metrics) == 3

        metric_0 = payload.metrics[0]
        assert isinstance(metric_0, TelemetryMetric)
        assert metric_0.metric_name == "rtt_latency"
        assert metric_0.value == pytest.approx(14.5)
        assert metric_0.unit == "ms"
        assert metric_0.timestamp == "2026-10-31T14:00:00Z"
        assert metric_0.device_id == "router-core-alpha"

        metric_1 = payload.metrics[1]
        assert metric_1.metric_name == "interface_utilization"
        assert metric_1.value == pytest.approx(87.2)
        assert metric_1.unit == "%"

        metric_2 = payload.metrics[2]
        assert metric_2.metric_name == "egress_throughput"
        assert metric_2.value == pytest.approx(940.0)
        assert metric_2.unit == "Mbps"
        assert metric_2.device_id == "router-core-beta"

    def test_valid_payload_with_empty_metrics(self) -> None:
        raw_input = {
            "scenario_id": "empty_scenario",
            "target_device": "switch-access-01",
            "metadata": {"test": "baseline"},
            "metrics": [],
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert payload.scenario_id == "empty_scenario"
        assert payload.target_device == "switch-access-01"
        assert payload.metrics == []
        assert payload.metadata == {"test": "baseline"}


class TestMissingOptionalFields:
    """
    Test suite validating handling of missing optional and required fields.
    """

    def test_missing_timestamp_in_metric(self) -> None:
        raw_input = {
            "scenario_id": "scen_no_timestamp",
            "target_device": "switch-01",
            "metrics": [
                {
                    "metric_name": "packet_loss",
                    "value": 1.5,
                    "unit": "%",
                    "device_id": "switch-01",
                }
            ],
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert len(payload.metrics) == 1
        assert payload.metrics[0].timestamp is None

    def test_missing_device_id_defaults_to_target_device(self) -> None:
        raw_input = {
            "scenario_id": "scen_default_device",
            "target_device": "agg-switch-04",
            "metrics": [
                {
                    "metric_name": "cpu_utilization",
                    "value": 65.0,
                    "unit": "%",
                }
            ],
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert len(payload.metrics) == 1
        assert payload.metrics[0].device_id == "agg-switch-04"

    def test_missing_metadata_defaults_to_empty_dict(self) -> None:
        raw_input = {
            "scenario_id": "scen_no_metadata",
            "target_device": "edge-fw-01",
            "metrics": [],
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert payload.metadata == {}

    def test_missing_scenario_and_target_device_defaults(self) -> None:
        raw_input = {
            "metrics": [
                {
                    "metric_name": "crc_errors",
                    "value": 3.0,
                    "unit": "count",
                }
            ]
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert payload.scenario_id == "unknown_scenario"
        assert payload.target_device == "unknown_device"
        assert len(payload.metrics) == 1
        assert payload.metrics[0].device_id == "unknown_device"

    def test_empty_dictionary_payload(self) -> None:
        payload = validate_and_sanitize_payload({})

        assert isinstance(payload, RawTelemetryPayload)
        assert payload.scenario_id == "unknown_scenario"
        assert payload.target_device == "unknown_device"
        assert payload.metrics == []
        assert payload.metadata == {}

    @pytest.mark.parametrize("invalid_input", [None, [], "raw string input", 999])
    def test_non_dict_payload_never_crashes(self, invalid_input) -> None:
        payload = validate_and_sanitize_payload(invalid_input)

        assert isinstance(payload, RawTelemetryPayload)
        assert payload.scenario_id == "unknown_scenario"
        assert payload.target_device == "unknown_device"
        assert payload.metrics == []
        assert "ingestion_error" in payload.metadata


class TestDirtyDataAndUnitNormalization:
    """
    Test suite validating dirty value parsing, unit conversions, and item dropping.
    """

    def test_stringified_number_conversion(self) -> None:
        raw_input = {
            "scenario_id": "dirty_string_numbers",
            "target_device": "router-wan-01",
            "metrics": [
                {
                    "metric_name": "float_string",
                    "value": "12.75",
                    "unit": "ms",
                },
                {
                    "metric_name": "int_string",
                    "value": " 200 ",
                    "unit": "ms",
                },
                {
                    "metric_name": "comma_separated_number",
                    "value": "1,500.25",
                    "unit": "bps",
                },
            ],
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert len(payload.metrics) == 3
        assert payload.metrics[0].value == pytest.approx(12.75)
        assert payload.metrics[1].value == pytest.approx(200.0)
        assert payload.metrics[2].value == pytest.approx(1500.25)

    def test_unit_normalization_seconds_to_milliseconds(self) -> None:
        raw_input = {
            "scenario_id": "unit_norm_latency",
            "target_device": "gw-01",
            "metrics": [
                {
                    "metric_name": "rtt_secs",
                    "value": 0.045,
                    "unit": "s",
                },
                {
                    "metric_name": "jitter_second",
                    "value": "0.012",
                    "unit": "sec",
                },
                {
                    "metric_name": "delay_seconds_full",
                    "value": 1.5,
                    "unit": "seconds",
                },
            ],
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert len(payload.metrics) == 3
        assert payload.metrics[0].value == pytest.approx(45.0)
        assert payload.metrics[0].unit == "ms"

        assert payload.metrics[1].value == pytest.approx(12.0)
        assert payload.metrics[1].unit == "ms"

        assert payload.metrics[2].value == pytest.approx(1500.0)
        assert payload.metrics[2].unit == "ms"

    def test_unit_normalization_microseconds_to_milliseconds(self) -> None:
        raw_input = {
            "scenario_id": "unit_norm_us",
            "target_device": "gw-02",
            "metrics": [
                {
                    "metric_name": "fast_rtt",
                    "value": 750.0,
                    "unit": "us",
                },
                {
                    "metric_name": "micro_delay",
                    "value": 2500.0,
                    "unit": "microseconds",
                },
            ],
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert len(payload.metrics) == 2
        assert payload.metrics[0].value == pytest.approx(0.75)
        assert payload.metrics[0].unit == "ms"

        assert payload.metrics[1].value == pytest.approx(2.5)
        assert payload.metrics[1].unit == "ms"

    def test_unit_normalization_percentages_and_ratios(self) -> None:
        raw_input = {
            "scenario_id": "unit_norm_pct",
            "target_device": "gw-03",
            "metrics": [
                {
                    "metric_name": "loss_pct",
                    "value": 3.4,
                    "unit": "pct",
                },
                {
                    "metric_name": "cpu_percent",
                    "value": 72.0,
                    "unit": "PERCENT",
                },
                {
                    "metric_name": "ratio_metric",
                    "value": 0.88,
                    "unit": "ratio",
                },
            ],
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert len(payload.metrics) == 3
        assert payload.metrics[0].value == pytest.approx(3.4)
        assert payload.metrics[0].unit == "%"

        assert payload.metrics[1].value == pytest.approx(72.0)
        assert payload.metrics[1].unit == "%"

        assert payload.metrics[2].value == pytest.approx(88.0)
        assert payload.metrics[2].unit == "%"

    def test_unit_normalization_throughput_casing(self) -> None:
        raw_input = {
            "scenario_id": "unit_norm_throughput",
            "target_device": "core-sw-01",
            "metrics": [
                {
                    "metric_name": "tx_rate",
                    "value": 500.0,
                    "unit": "MBPS",
                },
                {
                    "metric_name": "rx_rate",
                    "value": 10.0,
                    "unit": "gbps",
                },
            ],
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert len(payload.metrics) == 2
        assert payload.metrics[0].unit == "Mbps"
        assert payload.metrics[1].unit == "Gbps"

    def test_malformed_values_dropped_and_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        raw_input = {
            "scenario_id": "malformed_values_scen",
            "target_device": "leaf-01",
            "metrics": [
                {
                    "metric_name": "bad_string_metric",
                    "value": "N/A",
                    "unit": "ms",
                },
                {
                    "metric_name": "boolean_metric",
                    "value": True,
                    "unit": "ms",
                },
                {
                    "metric_name": "none_value_metric",
                    "value": None,
                    "unit": "ms",
                },
                {
                    "metric_name": "nan_metric",
                    "value": float("nan"),
                    "unit": "ms",
                },
                {
                    "metric_name": "inf_metric",
                    "value": float("inf"),
                    "unit": "ms",
                },
            ],
        }

        with caplog.at_level(logging.WARNING):
            payload = validate_and_sanitize_payload(raw_input)

        assert payload.metrics == []
        assert "invalid numeric value" in caplog.text

    def test_missing_metric_name_dropped(self, caplog: pytest.LogCaptureFixture) -> None:
        raw_input = {
            "scenario_id": "missing_name_scen",
            "target_device": "leaf-02",
            "metrics": [
                {
                    "value": 10.0,
                    "unit": "ms",
                },
                {
                    "metric_name": "   ",
                    "value": 20.0,
                    "unit": "ms",
                },
            ],
        }

        with caplog.at_level(logging.WARNING):
            payload = validate_and_sanitize_payload(raw_input)

        assert payload.metrics == []
        assert "missing or invalid 'metric_name'" in caplog.text

    def test_non_dict_metric_item_dropped(self, caplog: pytest.LogCaptureFixture) -> None:
        raw_input = {
            "scenario_id": "corrupt_items_scen",
            "target_device": "leaf-03",
            "metrics": [
                "unexpected string item",
                None,
                42,
                [1, 2, 3],
            ],
        }

        with caplog.at_level(logging.WARNING):
            payload = validate_and_sanitize_payload(raw_input)

        assert payload.metrics == []
        assert "item is not a dict" in caplog.text

    def test_partial_valid_and_malformed_metrics_preservation(self) -> None:
        raw_input = {
            "scenario_id": "mixed_scenario",
            "target_device": "spine-01",
            "metrics": [
                {
                    "metric_name": "valid_rtt",
                    "value": "0.025",
                    "unit": "s",
                },
                {
                    "metric_name": "corrupt_metric_1",
                    "value": "invalid_value",
                    "unit": "ms",
                },
                {
                    "metric_name": "valid_utilization",
                    "value": 91.5,
                    "unit": "%",
                },
                {
                    "value": 100.0,
                    "unit": "ms",
                },
                "completely invalid entry",
            ],
        }

        payload = validate_and_sanitize_payload(raw_input)

        assert len(payload.metrics) == 2
        assert payload.metrics[0].metric_name == "valid_rtt"
        assert payload.metrics[0].value == pytest.approx(25.0)
        assert payload.metrics[0].unit == "ms"

        assert payload.metrics[1].metric_name == "valid_utilization"
        assert payload.metrics[1].value == pytest.approx(91.5)
        assert payload.metrics[1].unit == "%"
