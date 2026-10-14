"""Stage 23 blind detector wrapper.

Reuses the frozen Stage-21 detector without retuning. The blind job receives
only label-free telemetry and a common-path negative-control projection.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage21_live_detect import FROZEN_STAGE21, detect as stage21_detect


def detect(external_rows: list[dict], common_rows: list[dict]) -> dict:
    if len(external_rows) != len(common_rows):
        raise ValueError("Stage23 telemetry/control length mismatch")
    if [row["tick"] for row in external_rows] != [
        row["tick"] for row in common_rows
    ]:
        raise ValueError("Stage23 telemetry/control tick mismatch")

    external = stage21_detect(external_rows)
    common = stage21_detect(common_rows)
    if external["seed"] != common["seed"]:
        raise ValueError("Stage23 telemetry/control seed mismatch")

    return {
        "seed": external["seed"],
        "protocol": {
            "private_labels_received": False,
            "detector_retuned_for_stage23": False,
            "frozen_stage21_semantic_config": dict(FROZEN_STAGE21.__dict__),
            "external_reference_scope": (
                "direct native NRF outside the native SCP process"
            ),
            "common_path_control_scope": (
                "both observations use the consumer-visible native-SCP state"
            ),
        },
        "external_reference": external,
        "common_path_control": common,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry", required=True)
    parser.add_argument("--common-path-telemetry", required=True)
    parser.add_argument("--output", default="stage23_detector")
    args = parser.parse_args()

    external = json.loads(Path(args.telemetry).read_text(encoding="utf8"))
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
        "STAGE23_BLIND_DETECT_OK "
        f"seed={result['seed']} external_alarms={ext_count} "
        f"common_path_alarms={common_count}",
        flush=True,
    )


if __name__ == "__main__":
    main()
