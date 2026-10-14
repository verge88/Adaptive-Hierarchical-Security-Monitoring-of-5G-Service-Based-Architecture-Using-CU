"""Stage 33 deterministic external-verifier policy."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from .stage27_authority import sha256_file
from .stage30_authority import EPOCH_SPECS

SCHEMA="stage33-external-verifier-policy-v1"

def canonical_bytes(doc:dict)->bytes:
    return json.dumps(doc,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf8")

def build_policy(root:Path)->dict:
    measured=[
        "stage33/render_verifier.py",
        "research/stage29_live_detect.py",
        "research/stage30_attestation.py",
        "research/stage30_live_detect.py",
        "live/stage28-nnrf-handler.c",
        "live/nssf.yaml",
        "live/nssf2.yaml",
    ]
    hashes={p:sha256_file(root/p) for p in measured}
    return {
        "stage":33,
        "schema":SCHEMA,
        "external_execution_domain":"Render web service with auto-deploy disabled",
        "decision_rule":"consumer NSSF cardinality or REGISTERED cardinality differs from approved epoch state",
        "common_source_negative_control":"consumer and compromised witness must be equal; external control alert is false",
        "legitimate_transition_region":[30,49],
        "attack_region_start_tick":50,
        "epochs":[
            {
                "epoch":int(s["epoch"]),
                "valid_from_tick":int(s["valid_from_tick"]),
                "valid_until_tick":int(s["valid_until_tick"]),
                "expected_nssf_count":int(s["expected_nssf_count"]),
                "expected_registered_count":int(s["expected_registered_count"]),
            }
            for s in EPOCH_SPECS
        ],
        "measurements_sha256":hashes,
        "private_key_location":"Render environment only; never committed or sent to GitHub",
        "claim_scope":"external verifier decision and signing key outside GitHub control plane; telemetry origin remains GitHub-hosted capture",
    }

def main():
    p=argparse.ArgumentParser(); p.add_argument("--output",default="stage33_policy"); a=p.parse_args()
    out=Path(a.output); out.mkdir(parents=True,exist_ok=True)
    doc=build_policy(Path(".")); raw=canonical_bytes(doc); digest=hashlib.sha256(raw).hexdigest()
    (out/"policy.json").write_bytes(raw)
    (out/"policy.pretty.json").write_text(json.dumps(doc,indent=2,ensure_ascii=False))
    (out/"policy.sha256").write_text(digest+"\n")
    print(f"STAGE33_POLICY_OK sha256={digest} measurements={len(doc['measurements_sha256'])}",flush=True)

if __name__=="__main__":
    main()
