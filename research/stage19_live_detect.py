"""Stage 19 frozen blind live detector.

Consumes only Stage-18-format label-free telemetry.  Stage-19 sparse parameters
were frozen from fresh synthetic development/validation before live seeds
8201..8206 are captured.

Outputs three competitors on the same telemetry:
- Stage-17 directional e-process;
- Stage-17 Page-Hinkley;
- Stage-19 stability-gated sparse directional quorum.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage18_detect import detect as stage18_detect
from .stage18_detect import signed_discrepancy
from .stage19_detector import (
    StabilityGatedQuorumConfig,
    StabilityGatedQuorumState,
)

WARMUP_TICKS = 30

FROZEN_STAGE19 = StabilityGatedQuorumConfig(
    stability_fraction_threshold=0.90,
    zero_epsilon=1e-12,
    window_ticks=16,
    required_hits=2,
    mismatch_epsilon=0.020,
)


def detect(rows: list[dict]) -> dict:
    baseline = stage18_detect(rows)
    calibration = [
        signed_discrepancy(row)
        for row in rows[:WARMUP_TICKS]
    ]
    state = StabilityGatedQuorumState(
        calibration,
        FROZEN_STAGE19,
    )

    outputs = []
    baseline_by_tick = {
        int(row["tick"]): row
        for row in baseline["ticks"]
    }

    for row in rows:
        tick = int(row["tick"])
        signed = signed_discrepancy(row)
        base = baseline_by_tick[tick]

        if tick < WARMUP_TICKS:
            stage19_alert = False
            stage19_state = {
                "quorum_enabled": state.quorum_enabled,
                "stable_fraction": state.stable_fraction,
            }
        else:
            stage19_state = state.observe(signed)
            stage19_alert = stage19_state["alert"]

        outputs.append(
            {
                "tick": tick,
                "signed_integrity_discrepancy": signed,
                "page_hinkley_alert": base[
                    "page_hinkley_alert"
                ],
                "stage17_directional_alert": base[
                    "directional_alert"
                ],
                "stage19_sparse_directional_alert": (
                    stage19_alert
                ),
                "stage19_quorum_enabled": (
                    state.quorum_enabled
                ),
                "stage19_stable_fraction": (
                    state.stable_fraction
                ),
                "stage19_positive_quorum_hits": (
                    stage19_state.get(
                        "positive_quorum_hits", 0
                    )
                ),
                "stage19_negative_quorum_hits": (
                    stage19_state.get(
                        "negative_quorum_hits", 0
                    )
                ),
            }
        )

    return {
        "seed": baseline["seed"],
        "protocol": {
            "private_labels_received": False,
            "live_seeds": [8201, 8206],
            "frozen_stage19_config": dict(
                FROZEN_STAGE19.__dict__
            ),
            "stage18_live_artifacts_used_for_tuning": False,
        },
        "calibration": {
            "stage19_quorum_enabled": state.quorum_enabled,
            "stage19_stable_fraction": state.stable_fraction,
        },
        "ticks": outputs,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry", required=True)
    parser.add_argument(
        "--output",
        default="stage19_detector",
    )
    args = parser.parse_args()

    rows = json.loads(
        Path(args.telemetry).read_text(encoding="utf8")
    )
    result = detect(rows)

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    (root / "alarms.json").write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )

    counts = {
        key: sum(row[key] for row in result["ticks"])
        for key in (
            "page_hinkley_alert",
            "stage17_directional_alert",
            "stage19_sparse_directional_alert",
        )
    }
    print(
        "STAGE19_BLIND_DETECT_OK "
        f"seed={result['seed']} "
        f"quorum_enabled={result['calibration']['stage19_quorum_enabled']} "
        f"alarms={counts}",
        flush=True,
    )


if __name__ == "__main__":
    main()
