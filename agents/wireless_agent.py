"""
agents/wireless_agent.py
Wireless 802.11 RF physical and link layer domain agent for NetCoop AI.
Monitors RSSI signal strength, Signal-to-Noise Ratio (SNR), and packet retransmission rates.
"""

from typing import Dict, List, Optional
from datetime import datetime

from agents.base import BaseAgent
from core.schemas import AgentFinding, MetricEvidence, RawTelemetryPayload, TelemetryMetric
from core.timeutils import is_newer

_is_newer = is_newer


class WirelessAgent(BaseAgent):
    """
    Analyzes wireless 802.11 Wi-Fi telemetry to diagnose RF path loss,
    co-channel interference, boundary coverage attenuation, and frame retransmission storms.
    """

    # Domain threshold constants
    RSSI_WEAK_THRESHOLD_DBM: float = -75.0
    SNR_WEAK_THRESHOLD_DB: float = 15.0
    RETRANSMISSION_THRESHOLD_PCT: float = 10.0

    # Recognized unit variations
    _DBM_UNITS = frozenset({"dbm", "db-m", "db_m", "dimensionless", ""})
    _DB_UNITS = frozenset({"db", "decibels", "decibel", "dimensionless", ""})
    _PERCENT_UNITS = frozenset({"%", "pct", "percent", "percentage", "ratio", "fraction"})

    def __init__(self, name: Optional[str] = None) -> None:
        super().__init__(name=name or "WirelessAgent")

    def _extract_canonical_metrics(
        self,
        metrics: List[TelemetryMetric],
        target_device: Optional[str] = None,
    ) -> Dict[str, TelemetryMetric]:
        """
        Normalize metric name variations to canonical wireless keys.
        Filters specifically for target_device and retains newest timestamped sample.
        """
        mapping: Dict[str, TelemetryMetric] = {}
        for m in metrics:
            if target_device and m.device_id and m.device_id.strip().lower() != target_device.strip().lower():
                continue

            name_clean = m.metric_name.lower().strip()
            canonical_key: Optional[str] = None

            if name_clean in {
                "rssi_dbm", "rssi", "signal_strength_dbm", "rx_power_dbm",
                "wifi_rssi_dbm", "wireless_rssi", "signal_dbm"
            }:
                canonical_key = "rssi"
            elif name_clean in {
                "snr_db", "snr", "signal_to_noise_ratio", "snr_ratio_db",
                "wifi_snr_db", "wireless_snr"
            }:
                canonical_key = "snr"
            elif name_clean in {
                "retransmission_rate_pct", "retransmission_rate", "retransmissions_pct",
                "retransmission_pct", "retry_rate_pct", "retry_rate", "wifi_retry_rate_pct",
                "packet_retry_pct"
            }:
                canonical_key = "retransmission_rate"

            if canonical_key is not None:
                if canonical_key not in mapping or _is_newer(m, mapping[canonical_key]):
                    mapping[canonical_key] = m

        return mapping

    def analyze(self, payload: RawTelemetryPayload) -> AgentFinding:
        """
        Evaluate wireless metrics against domain thresholds and unit standards.
        """
        target_device = payload.target_device

        if not payload.metrics:
            limitations: List[str] = []
            if "ingestion_notes" in payload.metadata and payload.metadata["ingestion_notes"]:
                limitations.extend(payload.metadata["ingestion_notes"])
            elif "ingestion_error" in payload.metadata:
                limitations.append(str(payload.metadata["ingestion_error"]))
            elif "validation_error" in payload.metadata:
                limitations.append(str(payload.metadata["validation_error"]))
            else:
                limitations.append("metrics list was empty in payload")

            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis=f"No wireless telemetry metrics provided in payload ({limitations[0] if limitations else 'no metrics'}).",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[target_device] if target_device else [],
                limitations=limitations,
            )

        wireless_map = self._extract_canonical_metrics(payload.metrics, target_device=target_device)
        if not wireless_map:
            return AgentFinding(
                agent_name=self.name,
                status="insufficient_evidence",
                hypothesis=f"No recognizable 802.11 wireless metrics (RSSI, SNR, Retransmission Rate) found for '{target_device}'.",
                confidence=0.0,
                supporting_evidence=[],
                affected_devices=[target_device] if target_device else [],
                limitations=["No recognized 802.11 Wi-Fi telemetry metrics matched for target device."],
            )

        evidence: List[MetricEvidence] = []
        anomalies: List[str] = []
        limitations: List[str] = []

        # 1. RSSI Evaluation (Weak if below -75 dBm)
        rssi_metric = wireless_map.get("rssi")
        weak_rssi = False
        if rssi_metric is not None:
            unit_clean = rssi_metric.unit.lower().strip()
            if unit_clean in self._DBM_UNITS:
                weak_rssi = rssi_metric.value < self.RSSI_WEAK_THRESHOLD_DBM
                evidence.append(
                    MetricEvidence(
                        metric=rssi_metric.metric_name,
                        value=rssi_metric.value,
                        canonical_key="rssi",
                        interpretation=(
                            f"Received signal strength ({rssi_metric.value:.1f} dBm) is degraded below threshold "
                            f"({self.RSSI_WEAK_THRESHOLD_DBM} dBm), indicating path loss or cell edge boundary."
                            if weak_rssi
                            else f"Received signal strength ({rssi_metric.value:.1f} dBm) is within nominal coverage boundaries."
                        ),
                    )
                )
                if weak_rssi:
                    anomalies.append("weak_rssi")
            else:
                limitations.append(f"RSSI metric unit '{rssi_metric.unit}' unverified; expected dBm.")

        # 2. SNR Evaluation (Weak if below 15 dB)
        snr_metric = wireless_map.get("snr")
        weak_snr = False
        if snr_metric is not None:
            unit_clean = snr_metric.unit.lower().strip()
            if unit_clean in self._DB_UNITS:
                weak_snr = snr_metric.value < self.SNR_WEAK_THRESHOLD_DB
                evidence.append(
                    MetricEvidence(
                        metric=snr_metric.metric_name,
                        value=snr_metric.value,
                        canonical_key="snr",
                        interpretation=(
                            f"Signal-to-Noise Ratio ({snr_metric.value:.1f} dB) is below threshold "
                            f"({self.SNR_WEAK_THRESHOLD_DB} dB), indicating high RF noise floor or interference."
                            if weak_snr
                            else f"Signal-to-Noise Ratio ({snr_metric.value:.1f} dB) indicates good RF channel quality."
                        ),
                    )
                )
                if weak_snr:
                    anomalies.append("low_snr")
            else:
                limitations.append(f"SNR metric unit '{snr_metric.unit}' unverified; expected dB.")

        # 3. Retransmission Rate Evaluation (High if above 10%)
        retrans_metric = wireless_map.get("retransmission_rate")
        high_retrans = False
        if retrans_metric is not None:
            unit_clean = retrans_metric.unit.lower().strip()
            norm_val = retrans_metric.value
            if unit_clean in {"ratio", "fraction"}:
                norm_val = norm_val * 100.0

            if unit_clean in self._PERCENT_UNITS or unit_clean in {"", "dimensionless"}:
                high_retrans = norm_val > self.RETRANSMISSION_THRESHOLD_PCT
                evidence.append(
                    MetricEvidence(
                        metric=retrans_metric.metric_name,
                        value=norm_val,
                        canonical_key="retransmission_rate",
                        interpretation=(
                            f"Wi-Fi frame retry rate ({norm_val:.1f}%) exceeds threshold "
                            f"({self.RETRANSMISSION_THRESHOLD_PCT}%), indicating collision storms or RF fading."
                            if high_retrans
                            else f"Wi-Fi frame retry rate ({norm_val:.1f}%) is within nominal operational boundaries."
                        ),
                    )
                )
                if high_retrans:
                    anomalies.append("high_retransmissions")
            else:
                limitations.append(f"Retransmission rate unit '{retrans_metric.unit}' unverified; expected percentage.")

        # Document missing expected wireless metrics
        expected_wireless = {"rssi", "snr", "retransmission_rate"}
        missing_keys = sorted(expected_wireless - wireless_map.keys())
        if missing_keys:
            limitations.append(f"Missing wireless metrics: {', '.join(missing_keys)}.")

        # Diagnostic Synthesis
        affected = [target_device] if target_device else []

        if anomalies:
            anomaly_descriptions = []
            if weak_rssi:
                anomaly_descriptions.append(f"weak RSSI (< {self.RSSI_WEAK_THRESHOLD_DBM} dBm)")
            if weak_snr:
                anomaly_descriptions.append(f"poor SNR (< {self.SNR_WEAK_THRESHOLD_DB} dB)")
            if high_retrans:
                anomaly_descriptions.append(f"excessive retransmissions (> {self.RETRANSMISSION_THRESHOLD_PCT}%)")

            # Calibrate confidence based on severity
            base_confidence = 0.88 + min(0.04 * len(anomalies), 0.08)

            return AgentFinding(
                agent_name=self.name,
                status="anomaly_detected",
                hypothesis=(
                    f"Wireless RF link degradation detected on '{target_device}': "
                    + "; ".join(anomaly_descriptions)
                    + "."
                ),
                confidence=round(base_confidence, 2),
                supporting_evidence=evidence,
                affected_devices=affected,
                limitations=limitations,
            )

        return AgentFinding(
            agent_name=self.name,
            status="healthy",
            hypothesis=f"Wireless 802.11 RF physical parameters for '{target_device}' are nominal.",
            confidence=0.90,
            supporting_evidence=evidence,
            affected_devices=affected,
            limitations=limitations,
        )
