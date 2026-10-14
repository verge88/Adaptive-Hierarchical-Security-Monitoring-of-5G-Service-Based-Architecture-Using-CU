"""Stage 30 blind detector wrapper.

Stage 30 freezes the Stage-29 augmented detector and adds no new detection
parameter. Freshness is enforced entirely in the signed baseline verifier.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage29_live_detect import detect as stage29_detect


def detect(attested_rows: list[dict], compromised_rows: list[dict]) -> dict:
    result = stage29_detect(attested_rows, compromised_rows)
    result["protocol"].update(
        {
            "detector_retuned_for_stage30": False,
            "stage29_rule_frozen_for_stage30": True,
            "stage30_private_attack_schedule_received": False,
            "stage30_freshness_decision_made_in_verifier": True,
            "stage30_trusted_wall_clock_used": False,
            "stage30_goal": (
                "validate signed logical epoch freshness across legitimate "
                "NSSF deregistration, registration and restart"
            ),
        }
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attested-telemetry", required=True)
    parser.add_argument("--compromised-pair-telemetry", required=True)
    parser.add_argument("--output", default="stage30_detector")
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
        "STAGE30_BLIND_DETECT_OK "
        f"seed={result['seed']} "
        f"augmented={sum(bool(r['stage29_augmented_alert']) for r in ext)} "
        f"pair_augmented={sum(bool(r['stage29_augmented_alert']) for r in pair)}",
        flush=True,
    )


if __name__ == "__main__":
    main()
