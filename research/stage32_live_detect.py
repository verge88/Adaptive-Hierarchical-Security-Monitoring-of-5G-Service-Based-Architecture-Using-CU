"""Stage 32 blind detector wrapper.

No detector changes. Stage 29 augmented detection, Stage 30 freshness, and
Stage 31 bundle provenance remain frozen; Stage 32 changes only the external
root-of-trust layer.
"""
from __future__ import annotations

import argparse, json
from pathlib import Path
from .stage31_live_detect import detect as stage31_detect


def detect(attested_rows: list[dict], compromised_rows: list[dict]) -> dict:
    result = stage31_detect(attested_rows, compromised_rows)
    result["protocol"].update({
        "detector_retuned_for_stage32": False,
        "stage29_rule_frozen_for_stage32": True,
        "stage30_freshness_protocol_frozen_for_stage32": True,
        "stage31_bundle_provenance_frozen_for_stage32": True,
        "stage32_private_attack_schedule_received": False,
        "stage32_goal": "validate external KMS/HSM-backed root without detector changes",
    })
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--attested-telemetry",required=True)
    p.add_argument("--compromised-pair-telemetry",required=True)
    p.add_argument("--output",default="stage32_detector")
    a=p.parse_args()
    att=json.loads(Path(a.attested_telemetry).read_text())
    comp=json.loads(Path(a.compromised_pair_telemetry).read_text())
    result=detect(att,comp)
    out=Path(a.output); out.mkdir(parents=True,exist_ok=True)
    (out/"alarms.json").write_text(json.dumps(result,indent=2))
    print("STAGE32_BLIND_DETECT_OK",flush=True)

if __name__=="__main__":
    main()
