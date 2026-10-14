"""Stage 27 blind detector wrapper.

The detector receives two label-free projections:
1) a verified signed-attestation reference versus the consumer NRF view;
2) the compromised NF-side witness versus the same consumer NRF view.

The frozen Stage-21 stack is reused without retuning.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage25_live_detect import detect as frozen_multichannel_detect


def detect(
    attested_rows: list[dict],
    compromised_pair_rows: list[dict],
) -> dict:
    result = frozen_multichannel_detect(
        attested_rows,
        compromised_pair_rows,
    )
    result["protocol"].update(
        {
            "private_labels_received": False,
            "detector_retuned_for_stage27": False,
            "stage27_attestation_private_key_received": False,
            "attested_reference_scope": (
                "verified signed software-rooted NSSF cardinality baseline"
            ),
            "compromised_pair_scope": (
                "colluding native NRF and NF-side witness software"
            ),
        }
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attested-telemetry", required=True)
    parser.add_argument("--compromised-pair-telemetry", required=True)
    parser.add_argument("--output", default="stage27_detector")
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

    attested_count = sum(
        bool(row["stage21_combined_alert"])
        for row in result["external_reference"]["ticks"]
    )
    compromised_count = sum(
        bool(row["stage21_combined_alert"])
        for row in result["common_path_control"]["ticks"]
    )
    print(
        "STAGE27_BLIND_DETECT_OK "
        f"seed={result['seed']} "
        f"attested_alarms={attested_count} "
        f"compromised_pair_alarms={compromised_count}",
        flush=True,
    )


if __name__ == "__main__":
    main()
