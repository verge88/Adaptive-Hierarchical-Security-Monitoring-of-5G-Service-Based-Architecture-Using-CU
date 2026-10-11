"""Stage 18 blind detector.

This module consumes ONLY label-free telemetry. It does not import the Stage-18
fault gateway, private schedule, attack kinds, or label files.

The sequential recurrences and thresholds are frozen from Stage 17:
- directional e-process: decay=.90, reference=.12, threshold=5.0, gate=.06
- Page-Hinkley: delta=.50, threshold=8.0, gate=.08, mean_alpha=.10

For the live transport experiment the monitored scalar is canonical JSON byte
accounting: consumer-visible bytes versus an independent nearby native-SCP
reference request. This preserves the signed-integrity principle while avoiding
any dependency on synthetic Stage-16 passive features.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from .stage15_detector import (
    power_betting_mixture,
    upper_tail_rank,
)

WARMUP_TICKS = 30

DIRECTIONAL_DECAY = 0.90
DIRECTIONAL_REFERENCE = 0.12
DIRECTIONAL_THRESHOLD = 5.0
DIRECTIONAL_GATE_P = 0.06

PH_DELTA = 0.50
PH_THRESHOLD = 8.0
PH_GATE_P = 0.08
PH_MEAN_ALPHA = 0.10


def lower_tail_rank(calibration: list[float], value: float) -> float:
    return (
        1 + sum(item <= value for item in calibration)
    ) / (len(calibration) + 1)


def signed_discrepancy(row: dict) -> float:
    trusted = max(1, int(row["trusted_canonical_bytes"]))
    consumer = int(row["consumer_canonical_bytes"])
    return (consumer - trusted) / trusted


def absolute_discrepancy(row: dict) -> float:
    return abs(signed_discrepancy(row))


def detect(rows: list[dict]) -> dict:
    if len(rows) <= WARMUP_TICKS:
        raise ValueError("Stage18 telemetry shorter than warm-up")
    if [row["tick"] for row in rows] != list(range(len(rows))):
        raise ValueError("Stage18 telemetry ticks are not contiguous")
    if any(
        row["trusted_status"] != 200
        or row["consumer_status"] != 200
        for row in rows
    ):
        raise ValueError("Stage18 detector requires successful live HTTP2 rows")

    signed_calibration = [
        signed_discrepancy(row)
        for row in rows[:WARMUP_TICKS]
    ]
    absolute_calibration = [
        abs(value) for value in signed_calibration
    ]

    positive = 0.0
    negative = 0.0

    ph_mean = 1.0
    ph_cumulative = 0.0
    ph_minimum = 0.0

    outputs = []

    for row in rows:
        tick = row["tick"]
        signed = signed_discrepancy(row)
        absolute = abs(signed)

        record = {
            "tick": tick,
            "signed_integrity_discrepancy": signed,
            "absolute_integrity_discrepancy": absolute,
            "directional_alert": False,
            "page_hinkley_alert": False,
        }

        if tick < WARMUP_TICKS:
            record["phase"] = "warmup"
            outputs.append(record)
            continue

        record["phase"] = "monitor"

        p_positive = upper_tail_rank(
            signed_calibration, signed
        )
        p_negative = lower_tail_rank(
            signed_calibration, signed
        )
        p_absolute = upper_tail_rank(
            absolute_calibration, absolute
        )

        log_e_positive = math.log(
            max(
                1e-12,
                power_betting_mixture(p_positive),
            )
        )
        log_e_negative = math.log(
            max(
                1e-12,
                power_betting_mixture(p_negative),
            )
        )

        positive = max(
            0.0,
            DIRECTIONAL_DECAY * positive
            + log_e_positive
            - DIRECTIONAL_REFERENCE,
        )
        negative = max(
            0.0,
            DIRECTIONAL_DECAY * negative
            + log_e_negative
            - DIRECTIONAL_REFERENCE,
        )

        directional_alert = (
            (
                positive >= DIRECTIONAL_THRESHOLD
                and p_positive <= DIRECTIONAL_GATE_P
            )
            or (
                negative >= DIRECTIONAL_THRESHOLD
                and p_negative <= DIRECTIONAL_GATE_P
            )
        )
        if directional_alert:
            positive = 0.0
            negative = 0.0

        surprise = -math.log(max(1e-12, p_absolute))
        ph_mean = (
            (1.0 - PH_MEAN_ALPHA) * ph_mean
            + PH_MEAN_ALPHA * surprise
        )
        ph_cumulative += (
            surprise - ph_mean - PH_DELTA
        )
        ph_minimum = min(ph_minimum, ph_cumulative)
        ph_statistic = ph_cumulative - ph_minimum
        page_hinkley_alert = (
            ph_statistic >= PH_THRESHOLD
            and p_absolute <= PH_GATE_P
        )
        if page_hinkley_alert:
            ph_cumulative = 0.0
            ph_minimum = 0.0

        record.update(
            {
                "p_positive": p_positive,
                "p_negative": p_negative,
                "p_absolute": p_absolute,
                "positive_e_state": positive,
                "negative_e_state": negative,
                "page_hinkley_statistic": ph_statistic,
                "directional_alert": directional_alert,
                "page_hinkley_alert": page_hinkley_alert,
            }
        )
        outputs.append(record)

    return {
        "protocol": {
            "detector_received_private_labels": False,
            "warmup_ticks": WARMUP_TICKS,
            "signal": (
                "signed canonical consumer JSON bytes minus "
                "independent native-SCP reference bytes"
            ),
            "directional_frozen_config": {
                "decay": DIRECTIONAL_DECAY,
                "reference": DIRECTIONAL_REFERENCE,
                "threshold": DIRECTIONAL_THRESHOLD,
                "direction_gate_p": DIRECTIONAL_GATE_P,
            },
            "page_hinkley_frozen_config": {
                "delta": PH_DELTA,
                "threshold": PH_THRESHOLD,
                "integrity_gate_p": PH_GATE_P,
                "mean_alpha": PH_MEAN_ALPHA,
            },
        },
        "calibration": {
            "signed_min": min(signed_calibration),
            "signed_max": max(signed_calibration),
            "signed_zero_count": sum(
                value == 0.0
                for value in signed_calibration
            ),
        },
        "ticks": outputs,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--telemetry",
        required=True,
    )
    parser.add_argument(
        "--output",
        default="stage18_detector",
    )
    args = parser.parse_args()

    telemetry_path = Path(args.telemetry)
    rows = json.loads(telemetry_path.read_text(encoding="utf8"))

    result = detect(rows)
    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    (root / "alarms.json").write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )

    directional = sum(
        row["directional_alert"]
        for row in result["ticks"]
    )
    page = sum(
        row["page_hinkley_alert"]
        for row in result["ticks"]
    )
    print(
        "STAGE18_BLIND_DETECT_OK "
        f"ticks={len(rows)} directional_alarms={directional} "
        f"page_hinkley_alarms={page}",
        flush=True,
    )


if __name__ == "__main__":
    main()
