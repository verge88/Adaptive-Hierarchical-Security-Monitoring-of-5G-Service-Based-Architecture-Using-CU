"""Stage 29 held-out capture wrapper.

Stage 29 deliberately freezes the Stage-28 randomized attack generator and
native Open5GS NRF instrumentation. Only fresh runner identifiers and fresh
system-random private schedules are used.

The Stage-28 block is treated as an exploratory/design set. Stage 29 is the
held-out validation set for the new attested-invariant channel.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .stage28_capture import capture as stage28_capture


async def capture(seed: int):
    raw_rows, labels, provenance, nrf_log = await stage28_capture(seed)
    labels = dict(labels)
    provenance = dict(provenance)
    labels["stage"] = 29
    labels["stage29_role"] = "held_out_validation"
    labels["attack_distribution_frozen_from_stage28"] = True
    provenance["stage"] = 29
    provenance["stage29_role"] = "held_out_validation"
    provenance["attack_generator_frozen_from_stage28"] = True
    provenance["detector_design_data_excluded_from_stage29_labels"] = True
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
        "STAGE29_CAPTURE_OK "
        f"seed={args.seed} ticks={len(raw_rows)} "
        f"episodes={len(labels['episodes'])} "
        f"mutations={labels['native_nrf_inprocess_log_marker_count']}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage29_raw")
    parser.add_argument("--labels-output", default="stage29_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
