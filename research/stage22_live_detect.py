"""Stage 22 blind detector wrapper.

The detector is intentionally not retuned.  It reuses the frozen Stage-21
multichannel detector on two label-free views:
1) an external reference that bypasses the SCP;
2) a common-path control where both observations are downstream of the same
   compromised-SCP view.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage21_live_detect import (
    FROZEN_STAGE21,
    detect as frozen_stage21_detect,
)


def detect(
    external_rows: list[dict],
    common_path_rows: list[dict],
) -> dict:
    if len(external_rows) != len(common_path_rows):
        raise ValueError("Stage22 telemetry/control length mismatch")
    if [row["tick"] for row in external_rows] != [
        row["tick"] for row in common_path_rows
    ]:
        raise ValueError("Stage22 telemetry/control ticks mismatch")

    external = frozen_stage21_detect(external_rows)
    common = frozen_stage21_detect(common_path_rows)
    if external["seed"] != common["seed"]:
        raise ValueError("Stage22 telemetry/control seed mismatch")

    return {
        "seed": external["seed"],
        "protocol": {
            "private_labels_received": False,
            "detector_retuned_for_stage22": False,
            "frozen_stage21_semantic_config": dict(
                FROZEN_STAGE21.__dict__
            ),
            "external_reference_scope": (
                "direct native NRF; bypasses the SCP trust domain"
            ),
            "common_path_control_scope": (
                "both observations share the same compromised-SCP view"
            ),
        },
        "external_reference": external,
        "common_path_control": common,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry", required=True)
    parser.add_argument(
        "--common-path-telemetry",
        required=True,
    )
    parser.add_argument(
        "--output",
        default="stage22_detector",
    )
    args = parser.parse_args()

    external_rows = json.loads(
        Path(args.telemetry).read_text(encoding="utf8")
    )
    common_path_rows = json.loads(
        Path(args.common_path_telemetry).read_text(encoding="utf8")
    )
    result = detect(external_rows, common_path_rows)

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    (root / "alarms.json").write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )

    ext = sum(
        row["stage21_combined_alert"]
        for row in result["external_reference"]["ticks"]
    )
    common = sum(
        row["stage21_combined_alert"]
        for row in result["common_path_control"]["ticks"]
    )
    print(
        "STAGE22_BLIND_DETECT_OK "
        f"seed={result['seed']} external_alarms={ext} "
        f"common_path_alarms={common}",
        flush=True,
    )


if __name__ == "__main__":
    main()
