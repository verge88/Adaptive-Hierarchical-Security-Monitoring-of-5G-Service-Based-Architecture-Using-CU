"""Stage 25 blind detector wrapper.

The detector is the frozen Stage-21 multichannel detector. Stage 25 changes only
the observation representation: both trusted and consumer views are projected
onto the same NRF-independent witness-supported fields before detection.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage20_live_detect import detect as stage20_detect
from .stage21_live_detect import FROZEN_STAGE21, detect as stage21_detect


def detect(external_rows: list[dict], common_rows: list[dict]) -> dict:
    if len(external_rows) != len(common_rows):
        raise ValueError("Stage25 telemetry/control length mismatch")
    if [row["tick"] for row in external_rows] != [
        row["tick"] for row in common_rows
    ]:
        raise ValueError("Stage25 telemetry/control tick mismatch")

    external = stage21_detect(external_rows)
    common = stage21_detect(common_rows)
    external20 = stage20_detect(external_rows)
    common20 = stage20_detect(common_rows)
    if external["seed"] != common["seed"]:
        raise ValueError("Stage25 telemetry/control seed mismatch")

    ext20 = {int(row["tick"]): row for row in external20["ticks"]}
    com20 = {int(row["tick"]): row for row in common20["ticks"]}
    for row in external["ticks"]:
        row["stage20_structural_alert"] = ext20[int(row["tick"])][
            "stage20_structural_alert"
        ]
    for row in common["ticks"]:
        row["stage20_structural_alert"] = com20[int(row["tick"])][
            "stage20_structural_alert"
        ]

    return {
        "seed": external["seed"],
        "protocol": {
            "private_labels_received": False,
            "detector_retuned_for_stage25": False,
            "frozen_stage21_semantic_config": dict(
                FROZEN_STAGE21.__dict__
            ),
            "reference_scope": (
                "common witness-supported projection built from NF-side "
                "registration identity and direct liveness outside NRF"
            ),
            "directional_numeric_reference_independent_of_nrf": True,
            "sparse_numeric_reference_independent_of_nrf": True,
            "structural_reference_independent_of_nrf": True,
            "semantic_reference_independent_of_nrf": True,
            "common_path_control_scope": (
                "all trusted projected fields replaced by the compromised "
                "NRF consumer projection"
            ),
        },
        "external_reference": external,
        "common_path_control": common,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry", required=True)
    parser.add_argument("--common-path-telemetry", required=True)
    parser.add_argument("--output", default="stage25_detector")
    args = parser.parse_args()

    external = json.loads(
        Path(args.telemetry).read_text(encoding="utf8")
    )
    common = json.loads(
        Path(args.common_path_telemetry).read_text(encoding="utf8")
    )
    result = detect(external, common)

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    (root / "alarms.json").write_text(
        json.dumps(result, indent=2), encoding="utf8"
    )

    keys = (
        "stage17_directional_alert",
        "stage19_sparse_directional_alert",
        "stage20_structural_alert",
        "stage21_semantic_alert",
        "stage21_combined_alert",
    )
    counts = {
        key: sum(
            row.get(key, False)
            for row in result["external_reference"]["ticks"]
        )
        for key in keys
    }
    print(
        "STAGE25_BLIND_DETECT_OK "
        f"seed={result['seed']} alarms={counts}",
        flush=True,
    )


if __name__ == "__main__":
    main()
