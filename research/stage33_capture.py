"""Stage 33 held-out capture wrapper."""
from __future__ import annotations
import argparse
import asyncio
import json
from pathlib import Path
from .stage32_capture import capture as stage32_capture

async def capture(seed: int):
    raw, labels, prov, log = await stage32_capture(seed)
    labels = dict(labels)
    prov = dict(prov)
    labels["stage"] = 33
    labels["stage33_role"] = "held_out_external_verifier_validation"
    prov["stage"] = 33
    prov["stage33_role"] = "held_out_external_verifier_validation"
    prov["stage32_external_root_design_frozen"] = True
    prov["stage30_freshness_protocol_frozen"] = True
    prov["stage29_detector_rule_frozen"] = True
    return raw, labels, prov, log

async def main_async(args):
    raw, labels, prov, log = await capture(args.seed)
    telemetry = Path(args.telemetry_output)
    labels_root = Path(args.labels_output)
    telemetry.mkdir(parents=True, exist_ok=True)
    labels_root.mkdir(parents=True, exist_ok=True)
    (telemetry / "raw_telemetry.json").write_text(
        json.dumps(raw, indent=2), encoding="utf8"
    )
    (telemetry / "provenance.json").write_text(
        json.dumps(prov, indent=2), encoding="utf8"
    )
    (labels_root / "private_labels.json").write_text(
        json.dumps(labels, indent=2), encoding="utf8"
    )
    (labels_root / "native_nrf_private.log").write_text(
        log, encoding="utf8"
    )
    print(
        f"STAGE33_CAPTURE_OK seed={args.seed} "
        f"ticks={len(raw)} episodes={len(labels['episodes'])}",
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
