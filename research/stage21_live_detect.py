"""Stage 21 frozen blind semantic-integrity detector.

The Stage-21 configuration is frozen from the successful signature-aware
development run before live seeds 8401..8408 are captured. This module imports
no private fault schedule or labels.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage20_live_detect import detect as stage20_detect
from .stage21_semantic import (
    SemanticQuorumConfig,
    SemanticQuorumState,
    deserialize_projection,
)

WARMUP_TICKS = 30
FROZEN_STAGE21 = SemanticQuorumConfig(
    paired_agreement_threshold=0.98,
    temporal_stability_threshold=0.90,
    window_ticks=16,
    required_hits=3,
    min_mismatched_paths=1,
    large_mismatched_paths=3,
    recovery_clean_ticks=2,
)


def row_pair(row: dict):
    return (
        deserialize_projection(row["trusted_semantic"]),
        deserialize_projection(row["consumer_semantic"]),
    )


def detect(rows: list[dict]) -> dict:
    if len(rows) <= WARMUP_TICKS:
        raise ValueError("Stage21 telemetry shorter than warm-up")

    baseline = stage20_detect(rows)
    baseline_by_tick = {
        int(row["tick"]): row for row in baseline["ticks"]
    }

    warmup_pairs = [
        row_pair(row) for row in rows[:WARMUP_TICKS]
    ]
    state = SemanticQuorumState(
        warmup_pairs, FROZEN_STAGE21
    )

    outputs = []
    for row in rows:
        tick = int(row["tick"])
        base = baseline_by_tick[tick]
        trusted, consumer = row_pair(row)

        if tick < WARMUP_TICKS:
            semantic_state = {
                "alert": False,
                "enabled": state.enabled,
                "selected_path_count": len(state.selected_paths),
                "mismatched_path_count": 0,
                "semantic_token_distance": 0,
                "semantic_signature": "",
                "signature_quorum_hits": 0,
                "in_recovery": False,
                "recovery_remaining": 0,
            }
        else:
            semantic_state = state.observe(
                trusted, consumer
            )

        stage20_alert = base["stage20_combined_alert"]
        semantic_alert = semantic_state["alert"]
        stage21_alert = stage20_alert or semantic_alert

        outputs.append(
            {
                "tick": tick,
                "page_hinkley_alert": base[
                    "page_hinkley_alert"
                ],
                "stage17_directional_alert": base[
                    "stage17_directional_alert"
                ],
                "stage19_sparse_directional_alert": base[
                    "stage19_sparse_directional_alert"
                ],
                "stage20_combined_alert": stage20_alert,
                "stage21_semantic_alert": semantic_alert,
                "stage21_combined_alert": stage21_alert,
                "semantic_channel_enabled": state.enabled,
                "semantic_selected_path_count": len(
                    state.selected_paths
                ),
                "semantic_mismatched_path_count": semantic_state[
                    "mismatched_path_count"
                ],
                "semantic_token_distance": semantic_state[
                    "semantic_token_distance"
                ],
                "semantic_signature_quorum_hits": semantic_state[
                    "signature_quorum_hits"
                ],
                "semantic_in_recovery": semantic_state[
                    "in_recovery"
                ],
                "semantic_recovery_remaining": semantic_state[
                    "recovery_remaining"
                ],
            }
        )

    seed = rows[0].get("seed")
    if any(row.get("seed") != seed for row in rows):
        raise ValueError("Stage21 telemetry mixes seeds")

    return {
        "seed": seed,
        "protocol": {
            "private_labels_received": False,
            "live_seeds": [8401, 8408],
            "frozen_stage21_config": dict(
                FROZEN_STAGE21.__dict__
            ),
            "historical_live_artifacts_used_for_tuning": False,
            "semantic_tokens_contain_raw_scalar_values": False,
            "semantic_digest_is_privacy_claim": False,
            "boundary_cross_entity_swap_expected_detectable": False,
        },
        "calibration": {
            "semantic_channel_enabled": state.enabled,
            "semantic_selected_path_count": len(
                state.selected_paths
            ),
            "semantic_selected_paths": list(
                state.selected_paths
            ),
        },
        "ticks": outputs,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry", required=True)
    parser.add_argument(
        "--output", default="stage21_detector"
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
            "stage20_combined_alert",
            "stage21_semantic_alert",
            "stage21_combined_alert",
        )
    }
    print(
        "STAGE21_BLIND_DETECT_OK "
        f"seed={result['seed']} "
        f"semantic_enabled={result['calibration']['semantic_channel_enabled']} "
        f"selected_paths={result['calibration']['semantic_selected_path_count']} "
        f"alarms={counts}",
        flush=True,
    )


if __name__ == "__main__":
    main()
