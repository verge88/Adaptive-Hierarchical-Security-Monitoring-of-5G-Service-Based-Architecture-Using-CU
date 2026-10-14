"""Stage 31 blind detector wrapper.

Stage 31 changes only authority-bundle provenance. The Stage-29 augmented
detector and Stage-30 freshness protocol remain frozen.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage30_live_detect import detect as stage30_detect


def detect(attested_rows: list[dict], compromised_rows: list[dict]) -> dict:
    result = stage30_detect(attested_rows, compromised_rows)
    result["protocol"].update(
        {
            "detector_retuned_for_stage31": False,
            "stage29_rule_frozen_for_stage31": True,
            "stage30_freshness_protocol_frozen_for_stage31": True,
            "stage31_private_attack_schedule_received": False,
            "stage31_goal": (
                "validate externally anchored provenance of the authority "
                "bundle without changing the detector"
            ),
        }
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attested-telemetry", required=True)
    parser.add_argument("--compromised-pair-telemetry", required=True)
    parser.add_argument("--output", default="stage31_detector")
    args = parser.parse_args()

    attested = json.loads(
        Path(args.attested_telemetry).read_text(encoding="utf8")
    )
    compromised = json.loads(
        Path(args.compromised_pair_telemetry).read_text(encoding="utf8")
    )
    result = detect(attested, compromised)

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    (root / "alarms.json").write_text(
        json.dumps(result, indent=2), encoding="utf8"
    )

    ext = result["external_reference"]["ticks"]
    pair = result["common_path_control"]["ticks"]
    print(
        "STAGE31_BLIND_DETECT_OK "
        f"seed={result['seed']} "
        f"augmented={sum(bool(r['stage29_augmented_alert']) for r in ext)} "
        f"pair_augmented={sum(bool(r['stage29_augmented_alert']) for r in pair)}",
        flush=True,
    )


if __name__ == "__main__":
    main()
