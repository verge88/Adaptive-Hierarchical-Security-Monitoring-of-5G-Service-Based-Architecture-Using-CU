"""Stage 30 software-rooted signed baseline epoch authority.

Stage 30 extends the Stage-27 software authority with a monotonic logical
freshness protocol. The authority signs a chain of discrete baseline epochs
covering a preregistered legitimate NF transition sequence.

Freshness is expressed in observation ticks, not wall-clock or hardware time.
This remains a software-rooted GitHub Actions experiment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from .stage27_authority import sha256_file

SCHEMA = "stage30-signed-baseline-epoch-v1"
EPOCH_SPECS = (
    {"epoch": 0, "valid_from_tick": 0, "valid_until_tick": 29,
     "expected_nssf_count": 2, "expected_registered_count": 2,
     "transition": "initial_two_nssf_registered"},
    {"epoch": 1, "valid_from_tick": 30, "valid_until_tick": 39,
     "expected_nssf_count": 1, "expected_registered_count": 1,
     "transition": "authorized_nssf2_deregistration"},
    {"epoch": 2, "valid_from_tick": 40, "valid_until_tick": 44,
     "expected_nssf_count": 2, "expected_registered_count": 2,
     "transition": "authorized_nssf2_registration"},
    {"epoch": 3, "valid_from_tick": 45, "valid_until_tick": 1000000,
     "expected_nssf_count": 2, "expected_registered_count": 2,
     "transition": "authorized_nssf1_restart_same_logical_state"},
)

def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def build_epoch_manifests(repo_root: Path) -> list[dict]:
    config_paths = {
        "nssf": repo_root / "live" / "nssf.yaml",
        "nssf2": repo_root / "live" / "nssf2.yaml",
    }
    for path in config_paths.values():
        if not path.is_file():
            raise FileNotFoundError(path)
    config_hashes = {
        name: sha256_file(path) for name, path in sorted(config_paths.items())
    }

    manifests = []
    previous_sha256 = None
    for spec in EPOCH_SPECS:
        manifest = {
            "stage": 30,
            "schema": SCHEMA,
            "authority_model": "github_actions_ephemeral_ed25519_epoch_chain",
            "open5gs_ref": "v2.7.6",
            "epoch": int(spec["epoch"]),
            "valid_from_tick": int(spec["valid_from_tick"]),
            "valid_until_tick": int(spec["valid_until_tick"]),
            "expected_nssf_count": int(spec["expected_nssf_count"]),
            "expected_registered_count": int(spec["expected_registered_count"]),
            "transition": str(spec["transition"]),
            "previous_manifest_sha256": previous_sha256,
            "config_sha256": config_hashes,
            "github_repository": os.environ.get("GITHUB_REPOSITORY", ""),
            "github_sha": os.environ.get("GITHUB_SHA", ""),
            "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "github_workflow": os.environ.get("GITHUB_WORKFLOW", ""),
            "freshness_model": (
                "monotonic signed logical observation epochs with "
                "non-overlapping validity intervals"
            ),
            "claim_scope": (
                "software-rooted baseline freshness for legitimate NSSF "
                "cardinality transitions; no trusted wall-clock or hardware measurement"
            ),
        }
        previous_sha256 = sha256_bytes(canonical_bytes(manifest))
        manifests.append(manifest)
    return manifests

def validate_static_chain(manifests: list[dict]) -> None:
    if not manifests:
        raise ValueError("Empty Stage30 baseline chain")
    previous_sha256 = None
    previous_until = -1
    for expected_epoch, manifest in enumerate(manifests):
        if int(manifest["epoch"]) != expected_epoch:
            raise ValueError("Stage30 epoch sequence is not contiguous")
        if manifest["schema"] != SCHEMA:
            raise ValueError("Stage30 epoch schema mismatch")
        if manifest["previous_manifest_sha256"] != previous_sha256:
            raise ValueError("Stage30 previous-manifest hash mismatch")
        start = int(manifest["valid_from_tick"])
        end = int(manifest["valid_until_tick"])
        if start != previous_until + 1:
            raise ValueError("Stage30 validity intervals are not contiguous")
        if end < start:
            raise ValueError("Stage30 epoch validity is inverted")
        previous_until = end
        previous_sha256 = sha256_bytes(canonical_bytes(manifest))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="stage30_authority")
    args = parser.parse_args()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    manifests = build_epoch_manifests(Path("."))
    validate_static_chain(manifests)

    index = {"stage": 30, "schema": SCHEMA, "epoch_count": len(manifests), "epochs": []}
    for manifest in manifests:
        epoch = int(manifest["epoch"])
        payload = canonical_bytes(manifest)
        filename = f"baseline-{epoch}.json"
        (output / filename).write_bytes(payload)
        index["epochs"].append({
            "epoch": epoch,
            "filename": filename,
            "sha256": sha256_bytes(payload),
            "valid_from_tick": manifest["valid_from_tick"],
            "valid_until_tick": manifest["valid_until_tick"],
        })

    (output / "index.json").write_text(
        json.dumps(index, indent=2), encoding="utf8"
    )
    print(
        "STAGE30_AUTHORITY_CHAIN_OK "
        f"epochs={len(manifests)} final_epoch={manifests[-1]['epoch']}",
        flush=True,
    )

if __name__ == "__main__":
    main()
