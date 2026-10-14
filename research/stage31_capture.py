"""Stage 31 held-out capture wrapper.

Stage 31 freezes the Stage-30 live transition and attack protocol. Only fresh
runner identifiers and fresh private randomized attack schedules are used.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .stage30_capture import capture as stage30_capture


async def capture(seed: int):
    raw_rows, labels, provenance, nrf_log = await stage30_capture(seed)
    labels = dict(labels)
    provenance = dict(provenance)
    labels["stage"] = 31
    labels["stage31_role"] = "held_out_github_attestation_validation"
    provenance["stage"] = 31
    provenance["stage31_role"] = "held_out_github_attestation_validation"
    provenance["stage30_freshness_protocol_frozen"] = True
    provenance["stage29_detector_rule_frozen"] = True
    return raw_rows, labels, provenance, nrf_log


async def main_async(args):
    raw_rows, labels, provenance, nrf_log = await capture(args.seed)

    telemetry_root = Path(args.telemetry_output)
    labels_root = Path(args.labels_output)
    telemetry_root.mkdir(parents=True, exist_ok=True)
    labels_root.mkdir(parents=True, exist_ok=True)

    (telemetry_root / "raw_telemetry.json").write_text(
        json.dumps(raw_rows, indent=2), encoding="utf8"
    )
    (telemetry_root / "provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf8"
    )
    (labels_root / "private_labels.json").write_text(
        json.dumps(labels, indent=2), encoding="utf8"
    )
    (labels_root / "native_nrf_private.log").write_text(
        nrf_log, encoding="utf8"
    )

    print(
        "STAGE31_CAPTURE_OK "
        f"seed={args.seed} ticks={len(raw_rows)} "
        f"attacks={len(labels['episodes'])}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage31_raw")
    parser.add_argument("--labels-output", default="stage31_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
