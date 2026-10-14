"""Stage 28 blind detector wrapper.

The attack distribution is randomized and private; the detector remains frozen.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage27_live_detect import detect as stage27_detect


def detect(attested_rows: list[dict], compromised_rows: list[dict]) -> dict:
    result = stage27_detect(attested_rows, compromised_rows)
    result["protocol"]["detector_retuned_for_stage28"] = False
    result["protocol"]["stage28_private_schedule_received"] = False
    result["protocol"]["stage28_goal"] = (
        "stress frozen detector under randomized duration, density, family "
        "and amplitude while preserving Stage27 trust mechanism"
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attested-telemetry", required=True)
    parser.add_argument("--compromised-pair-telemetry", required=True)
    parser.add_argument("--output", default="stage28_detector")
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

    print(
        "STAGE28_BLIND_DETECT_OK "
        f"seed={result['seed']} "
        f"attested_combined="
        f"{sum(bool(r['stage21_combined_alert']) for r in result['external_reference']['ticks'])} "
        f"compromised_combined="
        f"{sum(bool(r['stage21_combined_alert']) for r in result['common_path_control']['ticks'])}",
        flush=True,
    )


if __name__ == "__main__":
    main()
