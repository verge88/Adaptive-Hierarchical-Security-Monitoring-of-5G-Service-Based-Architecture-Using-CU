"""Stage 30 signed baseline-chain verifier and detector projector."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from .stage27_attestation import row_from_states, verify_ed25519
from .stage27_authority import sha256_file
from .stage30_authority import (
    EPOCH_SPECS,
    SCHEMA,
    canonical_bytes,
    sha256_bytes,
)


def validate_manifest_environment(manifest: dict) -> None:
    if int(manifest.get("stage", -1)) != 30:
        raise ValueError("Stage30 manifest stage mismatch")
    if manifest.get("schema") != SCHEMA:
        raise ValueError("Stage30 manifest schema mismatch")
    if manifest.get("open5gs_ref") != "v2.7.6":
        raise ValueError("Stage30 Open5GS baseline mismatch")

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    if repo and manifest.get("github_repository") != repo:
        raise ValueError("Stage30 manifest repository mismatch")
    if sha and manifest.get("github_sha") != sha:
        raise ValueError("Stage30 manifest commit mismatch")

    expected_hashes = {
        "nssf": sha256_file(Path("live/nssf.yaml")),
        "nssf2": sha256_file(Path("live/nssf2.yaml")),
    }
    if manifest.get("config_sha256") != expected_hashes:
        raise ValueError("Stage30 manifest config hash mismatch")


def load_and_verify_chain(authority_dir: Path) -> list[dict]:
    public_key = authority_dir / "public.pem"
    if not public_key.is_file():
        raise FileNotFoundError(public_key)

    manifests = []
    previous_sha = None
    previous_until = -1

    for spec in EPOCH_SPECS:
        epoch = int(spec["epoch"])
        manifest_path = authority_dir / f"baseline-{epoch}.json"
        signature_path = authority_dir / f"baseline-{epoch}.sig"
        if not manifest_path.is_file() or not signature_path.is_file():
            raise FileNotFoundError(
                f"Missing Stage30 signed epoch {epoch}"
            )

        verify_ed25519(
            manifest_path,
            signature_path,
            public_key,
        )
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw)
        if canonical_bytes(manifest) != raw:
            raise ValueError(
                f"Stage30 epoch {epoch} is not canonical JSON"
            )
        validate_manifest_environment(manifest)

        if int(manifest["epoch"]) != epoch:
            raise ValueError("Stage30 epoch number mismatch")
        if manifest["previous_manifest_sha256"] != previous_sha:
            raise ValueError("Stage30 epoch-chain hash mismatch")

        start = int(manifest["valid_from_tick"])
        end = int(manifest["valid_until_tick"])
        if start != previous_until + 1:
            raise ValueError("Stage30 epoch validity gap/overlap")
        if end < start:
            raise ValueError("Stage30 invalid epoch interval")

        if (
            int(manifest["expected_nssf_count"])
            != int(spec["expected_nssf_count"])
            or int(manifest["expected_registered_count"])
            != int(spec["expected_registered_count"])
            or start != int(spec["valid_from_tick"])
            or end != int(spec["valid_until_tick"])
        ):
            raise ValueError("Stage30 signed epoch differs from design lock")

        previous_sha = sha256_bytes(raw)
        previous_until = end
        manifests.append(manifest)

    return manifests


def baseline_for_tick(manifests: list[dict], tick: int) -> dict:
    matches = [
        manifest
        for manifest in manifests
        if int(manifest["valid_from_tick"])
        <= tick
        <= int(manifest["valid_until_tick"])
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Stage30 tick {tick} has {len(matches)} valid baselines"
        )
    return matches[0]


def candidate_is_fresh_for_tick(candidate: dict, tick: int) -> bool:
    return (
        int(candidate["valid_from_tick"])
        <= tick
        <= int(candidate["valid_until_tick"])
    )


def run_replay_audit(manifests: list[dict]) -> dict:
    attempts = []
    for epoch in range(1, len(manifests)):
        current = manifests[epoch]
        stale = manifests[epoch - 1]
        tick = int(current["valid_from_tick"])
        accepted = candidate_is_fresh_for_tick(stale, tick)
        attempts.append(
            {
                "kind": "previous_epoch_replay",
                "presented_epoch": int(stale["epoch"]),
                "current_epoch": int(current["epoch"]),
                "tick": tick,
                "accepted": accepted,
            }
        )

    rollback_tick = int(manifests[-1]["valid_from_tick"])
    rollback = manifests[0]
    attempts.append(
        {
            "kind": "multi_epoch_rollback",
            "presented_epoch": int(rollback["epoch"]),
            "current_epoch": int(manifests[-1]["epoch"]),
            "tick": rollback_tick,
            "accepted": candidate_is_fresh_for_tick(
                rollback, rollback_tick
            ),
        }
    )

    return {
        "attempts": attempts,
        "attempt_count": len(attempts),
        "accepted_count": sum(
            int(item["accepted"]) for item in attempts
        ),
        "rejected_count": sum(
            int(not item["accepted"]) for item in attempts
        ),
    }


def project(
    raw_rows: list[dict],
    manifests: list[dict],
) -> tuple[list[dict], list[dict]]:
    attested = []
    compromised = []

    for raw in raw_rows:
        tick = int(raw["tick"])
        manifest = baseline_for_tick(manifests, tick)
        epoch = int(manifest["epoch"])
        if int(raw["baseline_epoch"]) != epoch:
            raise ValueError(
                "Stage30 capture epoch marker disagrees with signed chain"
            )

        trusted = row_from_states(
            raw,
            int(manifest["expected_nssf_count"]),
            int(manifest["expected_registered_count"]),
            scope="verified_signed_fresh_epoch_baseline",
        )
        trusted["stage29_attestation_verified_reference"] = True
        trusted["stage30_baseline_epoch"] = epoch
        trusted["stage30_baseline_fresh"] = True

        pair = row_from_states(
            raw,
            int(raw["compromised_witness_nssf_count"]),
            int(raw["compromised_witness_registered_count"]),
            scope="colluding_nrf_and_nf_side_witness",
        )
        pair["stage29_attestation_verified_reference"] = False
        pair["stage30_baseline_epoch"] = epoch
        pair["stage30_baseline_fresh"] = False

        attested.append(trusted)
        compromised.append(pair)

    return attested, compromised


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-telemetry", required=True)
    parser.add_argument("--authority-dir", required=True)
    parser.add_argument("--output", default="stage30_projected")
    args = parser.parse_args()

    raw_rows = json.loads(
        Path(args.raw_telemetry).read_text(encoding="utf8")
    )
    if not raw_rows:
        raise ValueError("Empty Stage30 raw telemetry")
    seed = int(raw_rows[0]["seed"])
    if any(int(row["seed"]) != seed for row in raw_rows):
        raise ValueError("Mixed Stage30 seeds")

    authority_dir = Path(args.authority_dir)
    manifests = load_and_verify_chain(authority_dir)
    freshness = run_replay_audit(manifests)
    if freshness["accepted_count"] != 0:
        raise AssertionError("Stage30 stale/replay baseline was accepted")

    attested, compromised = project(raw_rows, manifests)

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "attested_telemetry.json").write_text(
        json.dumps(attested, indent=2), encoding="utf8"
    )
    (output / "compromised_pair_telemetry.json").write_text(
        json.dumps(compromised, indent=2), encoding="utf8"
    )
    (output / "freshness_audit.json").write_text(
        json.dumps(freshness, indent=2), encoding="utf8"
    )

    public_key = authority_dir / "public.pem"
    chain_hashes = [
        sha256_bytes(
            (authority_dir / f"baseline-{epoch}.json").read_bytes()
        )
        for epoch in range(len(manifests))
    ]
    provenance = {
        "stage": 30,
        "seed": seed,
        "attestation_algorithm": "Ed25519",
        "signed_epoch_chain_verified": True,
        "epoch_count": len(manifests),
        "epoch_sequence": [int(m["epoch"]) for m in manifests],
        "epoch_chain_sha256": chain_hashes,
        "authority_public_key_sha256": hashlib.sha256(
            public_key.read_bytes()
        ).hexdigest(),
        "authority_private_key_available_to_verifier": False,
        "authority_private_key_uploaded": False,
        "monotonic_logical_freshness_enforced": True,
        "trusted_wall_clock_used": False,
        "stale_replay_attempts": freshness["attempt_count"],
        "stale_replay_accepted": freshness["accepted_count"],
        "pairwise_common_source_equal_in_raw_input": all(
            int(row["consumer_nssf_count"])
            == int(row["compromised_witness_nssf_count"])
            and int(row["consumer_registered_count"])
            == int(row["compromised_witness_registered_count"])
            for row in raw_rows
        ),
        "realized_attack_schedule_available_to_verifier": False,
        "stage29_rule_frozen": True,
    }
    (output / "attestation_provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf8"
    )

    print(
        "STAGE30_FRESHNESS_VERIFY_OK "
        f"seed={seed} epochs={len(manifests)} "
        f"replay_rejected={freshness['rejected_count']}/"
        f"{freshness['attempt_count']}",
        flush=True,
    )


if __name__ == "__main__":
    main()
