"""Stage 21 frozen ablation detector.

Evaluation-only decomposition of the already frozen Stage-17/19/20/21
detectors. No private labels are imported or read.

Variants are computed on the same telemetry:
- directional_only
- directional_plus_sparse
- structural_only
- semantic_only
- directional_plus_structural
- full_without_semantic (Stage 20)
- full_without_structural
- full_without_sparse
- full (Stage 21)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage20_live_detect import detect as stage20_detect
from .stage21_live_detect import FROZEN_STAGE21, WARMUP_TICKS, row_pair
from .stage21_semantic import SemanticQuorumState


VARIANT_KEYS = (
    "directional_only",
    "directional_plus_sparse",
    "structural_only",
    "semantic_only",
    "directional_plus_structural",
    "full_without_semantic",
    "full_without_structural",
    "full_without_sparse",
    "full",
)


def detect(rows: list[dict]) -> dict:
    if len(rows) <= WARMUP_TICKS:
        raise ValueError("Stage21 ablation telemetry shorter than warm-up")

    stage20 = stage20_detect(rows)
    by_tick = {
        int(row["tick"]): row for row in stage20["ticks"]
    }

    warmup_pairs = [
        row_pair(row) for row in rows[:WARMUP_TICKS]
    ]
    semantic_state = SemanticQuorumState(
        warmup_pairs, FROZEN_STAGE21
    )

    outputs = []
    for row in rows:
        tick = int(row["tick"])
        base = by_tick[tick]
        trusted, consumer = row_pair(row)

        if tick < WARMUP_TICKS:
            semantic_alert = False
        else:
            semantic_alert = semantic_state.observe(
                trusted, consumer
            )["alert"]

        directional = bool(
            base["stage17_directional_alert"]
        )
        stage19 = bool(
            base["stage19_sparse_directional_alert"]
        )
        structural = bool(
            base["stage20_structural_alert"]
        )

        variants = {
            "directional_only": directional,
            "directional_plus_sparse": stage19,
            "structural_only": structural,
            "semantic_only": semantic_alert,
            "directional_plus_structural": (
                directional or structural
            ),
            "full_without_semantic": (
                stage19 or structural
            ),
            "full_without_structural": (
                stage19 or semantic_alert
            ),
            "full_without_sparse": (
                directional or structural or semantic_alert
            ),
            "full": (
                stage19 or structural or semantic_alert
            ),
        }
        outputs.append(
            {
                "tick": tick,
                **variants,
                "stage17_directional_alert": directional,
                "stage19_sparse_directional_alert": stage19,
                "structural_alert": structural,
                "semantic_alert": semantic_alert,
            }
        )

    seed = rows[0].get("seed")
    if any(row.get("seed") != seed for row in rows):
        raise ValueError("Stage21 ablation telemetry mixes seeds")

    return {
        "seed": seed,
        "protocol": {
            "private_labels_received": False,
            "evaluation_only": True,
            "detectors_retuned": False,
            "frozen_stage21_config": dict(
                FROZEN_STAGE21.__dict__
            ),
            "variants": list(VARIANT_KEYS),
        },
        "calibration": {
            "structural_channel_enabled": stage20[
                "calibration"
            ]["structural_channel_enabled"],
            "structural_exact_fraction": stage20[
                "calibration"
            ]["structural_exact_fraction"],
            "semantic_channel_enabled": semantic_state.enabled,
            "semantic_selected_path_count": len(
                semantic_state.selected_paths
            ),
        },
        "ticks": outputs,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry", required=True)
    parser.add_argument(
        "--output", default="stage21_ablation_detector"
    )
    args = parser.parse_args()

    rows = json.loads(
        Path(args.telemetry).read_text(encoding="utf8")
    )
    result = detect(rows)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "ablation_alarms.json").write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    counts = {
        key: sum(row[key] for row in result["ticks"])
        for key in VARIANT_KEYS
    }
    print(
        "STAGE21_ABLATION_DETECT_OK "
        f"seed={result['seed']} alarms={counts}",
        flush=True,
    )


if __name__ == "__main__":
    main()
