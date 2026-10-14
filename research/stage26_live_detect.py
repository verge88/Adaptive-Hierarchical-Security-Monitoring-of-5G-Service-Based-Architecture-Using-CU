"""Stage 26 blind detector wrapper for persistent NRF phantom profiles."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage25_live_detect import detect as stage25_detect


def detect(external_rows: list[dict], common_rows: list[dict]) -> dict:
    result = stage25_detect(external_rows, common_rows)
    result["protocol"]["detector_retuned_for_stage26"] = False
    result["protocol"]["stage26_attack_labels_received"] = False
    result["protocol"]["stage26_goal"] = (
        "validate frozen directional sensitivity under persistent "
        "NRF-generated canonical-byte shift"
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry", required=True)
    parser.add_argument("--common-path-telemetry", required=True)
    parser.add_argument("--output", default="stage26_detector")
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
            bool(row.get(key, False))
            for row in result["external_reference"]["ticks"]
        )
        for key in keys
    }
    print(
        "STAGE26_BLIND_DETECT_OK "
        f"seed={result['seed']} alarms={counts}",
        flush=True,
    )


if __name__ == "__main__":
    main()
