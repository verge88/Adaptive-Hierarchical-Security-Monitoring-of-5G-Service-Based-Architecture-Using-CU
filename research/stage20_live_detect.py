"""Stage 20 frozen blind live detector.

Combines the frozen Stage-19 byte-accounting detector with an independently
developed value-free structural fingerprint channel. Private labels are not
read or imported.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage19_live_detect import detect as stage19_detect
from .stage20_structure import (
    StructuralQuorumConfig,
    StructuralQuorumState,
    deserialize_counter,
    structural_difference,
)

WARMUP_TICKS = 30
FROZEN_STAGE20 = StructuralQuorumConfig(
    stability_fraction_threshold=0.98,
    window_ticks=12,
    required_hits=4,
    min_token_difference=1,
    large_difference_tokens=8,
)


def row_difference(row: dict):
    trusted = deserialize_counter(row["trusted_structure"])
    consumer = deserialize_counter(row["consumer_structure"])
    return structural_difference(trusted, consumer)


def detect(rows: list[dict]) -> dict:
    if len(rows) <= WARMUP_TICKS:
        raise ValueError("Stage20 telemetry shorter than warm-up")

    baseline = stage19_detect(rows)
    baseline_by_tick = {
        int(row["tick"]): row
        for row in baseline["ticks"]
    }

    warmup_diffs = [
        row_difference(row)
        for row in rows[:WARMUP_TICKS]
    ]
    state = StructuralQuorumState(
        warmup_diffs,
        FROZEN_STAGE20,
    )

    outputs = []
    for row in rows:
        tick = int(row["tick"])
        base = baseline_by_tick[tick]
        diff = row_difference(row)

        if tick < WARMUP_TICKS:
            structural_state = {
                "alert": False,
                "enabled": state.enabled,
                "exact_fraction": state.exact_fraction,
                "missing_tokens": diff.missing_tokens,
                "extra_tokens": diff.extra_tokens,
                "total_tokens": diff.total_tokens,
                "normalized_distance": diff.normalized_distance,
                "direction": diff.direction,
                "positive_quorum_hits": 0,
                "negative_quorum_hits": 0,
                "large_alert": False,
                "quorum_alert": False,
            }
        else:
            structural_state = state.observe(diff)

        stage19_alert = base[
            "stage19_sparse_directional_alert"
        ]
        structural_alert = structural_state["alert"]
        stage20_alert = stage19_alert or structural_alert

        outputs.append(
            {
                "tick": tick,
                "page_hinkley_alert": base[
                    "page_hinkley_alert"
                ],
                "stage17_directional_alert": base[
                    "stage17_directional_alert"
                ],
                "stage19_sparse_directional_alert": (
                    stage19_alert
                ),
                "stage20_structural_alert": structural_alert,
                "stage20_combined_alert": stage20_alert,
                "structural_channel_enabled": state.enabled,
                "structural_exact_fraction": state.exact_fraction,
                "structural_missing_tokens": (
                    structural_state["missing_tokens"]
                ),
                "structural_extra_tokens": (
                    structural_state["extra_tokens"]
                ),
                "structural_total_tokens": (
                    structural_state["total_tokens"]
                ),
                "structural_direction": (
                    structural_state["direction"]
                ),
                "structural_positive_quorum_hits": (
                    structural_state["positive_quorum_hits"]
                ),
                "structural_negative_quorum_hits": (
                    structural_state["negative_quorum_hits"]
                ),
            }
        )

    seed = rows[0].get("seed")
    if any(row.get("seed") != seed for row in rows):
        raise ValueError("Stage20 telemetry mixes seeds")

    return {
        "seed": seed,
        "protocol": {
            "private_labels_received": False,
            "live_seeds": [8301, 8306],
            "frozen_stage20_config": dict(
                FROZEN_STAGE20.__dict__
            ),
            "stage18_stage19_live_artifacts_used_for_tuning": False,
            "structural_fingerprint_contains_scalar_values": False,
        },
        "calibration": {
            "structural_channel_enabled": state.enabled,
            "structural_exact_fraction": state.exact_fraction,
        },
        "ticks": outputs,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry", required=True)
    parser.add_argument(
        "--output",
        default="stage20_detector",
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
            "stage19_sparse_directional_alert",
            "stage20_structural_alert",
            "stage20_combined_alert",
        )
    }
    print(
        "STAGE20_BLIND_DETECT_OK "
        f"seed={result['seed']} "
        f"structural_enabled={result['calibration']['structural_channel_enabled']} "
        f"alarms={counts}",
        flush=True,
    )


if __name__ == "__main__":
    main()
