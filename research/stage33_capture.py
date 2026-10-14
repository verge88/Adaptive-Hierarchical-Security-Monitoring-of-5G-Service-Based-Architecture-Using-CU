"""Stage 33 held-out capture wrapper.

The live Open5GS transition and randomized attack protocol is frozen from
Stages 30-32. Stage 33 changes only where trusted projection and detection are
executed: outside GitHub Actions in an independently administered verifier.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .stage32_capture import capture as stage32_capture


async def capture(seed: int):
    raw_rows, labels, provenance, nrf_log = await stage32_capture(seed)
    labels = dict(labels)
    provenance = dict(provenance)
    labels["stage"] = 33
    labels["stage33_role"] = "held_out_external_verifier_validation"
    provenance["stage"] = 33
    provenance["stage33_role"] = "held_out_external_verifier_validation"
    provenance["external_verifier_receives_private_labels"] = False
    provenance["stage29_detector_rule_frozen"] = True
    provenance["stage30_freshness_protocol_frozen"] = True
    provenance["stage28_attack_generator_frozen"] = True
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
        "STAGE33_CAPTURE_OK "
        f"seed={args.seed} ticks={len(raw_rows)} "
        f"episodes={len(labels['episodes'])}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage33_raw")
    parser.add_argument("--labels-output", default="stage33_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
