"""Stage 24 blind detector wrapper.

The detector is unchanged from Stage 21. Stage 24 supplies an NRF-independent
semantic witness derived from NF-side registration/liveness evidence, while
numeric and structural reference channels are deliberately neutralized.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage21_live_detect import FROZEN_STAGE21, detect as stage21_detect


def detect(external_rows: list[dict], common_rows: list[dict]) -> dict:
    if len(external_rows) != len(common_rows):
        raise ValueError("Stage24 telemetry/control length mismatch")
    if [row["tick"] for row in external_rows] != [
        row["tick"] for row in common_rows
    ]:
        raise ValueError("Stage24 telemetry/control tick mismatch")

    external = stage21_detect(external_rows)
    common = stage21_detect(common_rows)
    if external["seed"] != common["seed"]:
        raise ValueError("Stage24 telemetry/control seed mismatch")

    return {
        "seed": external["seed"],
        "protocol": {
            "private_labels_received": False,
            "detector_retuned_for_stage24": False,
            "frozen_stage21_semantic_config": dict(
                FROZEN_STAGE21.__dict__
            ),
            "external_reference_scope": (
                "NF-side registration logs plus direct NSSF liveness; "
                "does not query NRF discovery"
            ),
            "numeric_channel_neutralized": True,
            "structural_channel_neutralized": True,
            "semantic_channel_independent_of_nrf": True,
            "common_path_control_scope": (
                "trusted semantic view replaced by the same compromised-NRF "
                "consumer representation"
            ),
        },
        "external_reference": external,
        "common_path_control": common,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry", required=True)
    parser.add_argument("--common-path-telemetry", required=True)
    parser.add_argument("--output", default="stage24_detector")
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

    ext_count = sum(
        row["stage21_combined_alert"]
        for row in result["external_reference"]["ticks"]
    )
    common_count = sum(
        row["stage21_combined_alert"]
        for row in result["common_path_control"]["ticks"]
    )
    print(
        "STAGE24_BLIND_DETECT_OK "
        f"seed={result['seed']} external_alarms={ext_count} "
        f"common_path_alarms={common_count}",
        flush=True,
    )


if __name__ == "__main__":
    main()
