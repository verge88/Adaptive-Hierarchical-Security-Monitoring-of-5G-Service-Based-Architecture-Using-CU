"""Stage27 software-attestation invariants."""
from __future__ import annotations

import ast
import inspect
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from research.stage27_attestation import (
    project,
    validate_manifest,
    verify_ed25519,
)
from research.stage27_authority import (
    EXPECTED_NSSF_COUNT,
    EXPECTED_REGISTERED_COUNT,
    build_manifest,
    canonical_bytes,
)
from research.stage27_live_detect import detect


WARMUP = 30
EPISODE = 12
GAP = 4
CYCLES = 6
TOTAL = WARMUP + CYCLES * (EPISODE + GAP)


def synthetic_raw(seed: int = 99401) -> list[dict]:
    rows = []
    for tick in range(TOTAL):
        if tick < WARMUP:
            count = 2
        else:
            local = (tick - WARMUP) % (EPISODE + GAP)
            count = 3 if local < EPISODE else 2
        rows.append(
            {
                "seed": seed,
                "tick": tick,
                "witness_first": tick % 2 == 0,
                "consumer_nssf_count": count,
                "consumer_registered_count": count,
                "compromised_witness_nssf_count": count,
                "compromised_witness_registered_count": count,
                "common_source_equal": True,
            }
        )
    return rows


class Stage27Tests(unittest.TestCase):
    def test_authority_manifest_is_canonical_and_reviewable(self):
        manifest = build_manifest(Path("."))
        self.assertEqual(
            manifest["expected_nssf_count"], EXPECTED_NSSF_COUNT
        )
        self.assertEqual(
            manifest["expected_registered_count"],
            EXPECTED_REGISTERED_COUNT,
        )
        decoded = json.loads(canonical_bytes(manifest))
        self.assertEqual(decoded, manifest)
        self.assertEqual(set(manifest["logical_nssf_services"]), {"nssf", "nssf2"})

    def test_ed25519_signature_rejects_tampering(self):
        manifest = build_manifest(Path("."))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            manifest_path = root / "manifest.json"
            signature = root / "manifest.sig"

            manifest_path.write_bytes(canonical_bytes(manifest))
            subprocess.run(
                [
                    "openssl", "genpkey",
                    "-algorithm", "ED25519",
                    "-out", str(private_key),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "openssl", "pkey",
                    "-in", str(private_key),
                    "-pubout",
                    "-out", str(public_key),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "openssl", "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey", str(private_key),
                    "-in", str(manifest_path),
                    "-out", str(signature),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            verify_ed25519(manifest_path, signature, public_key)

            tampered = dict(manifest)
            tampered["expected_nssf_count"] = 3
            manifest_path.write_bytes(canonical_bytes(tampered))
            with self.assertRaises(ValueError):
                verify_ed25519(manifest_path, signature, public_key)

    def test_common_source_pair_fails_but_attestation_recovers(self):
        manifest = build_manifest(Path("."))
        raw = synthetic_raw()
        attested, compromised = project(raw, manifest)
        result = detect(attested, compromised)

        attested_ticks = result["external_reference"]["ticks"]
        pair_ticks = result["common_path_control"]["ticks"]

        self.assertTrue(
            any(
                row["stage21_combined_alert"]
                for row in attested_ticks[WARMUP:]
            )
        )
        self.assertFalse(
            any(
                row["stage21_combined_alert"]
                for row in pair_ticks
            )
        )
        self.assertTrue(
            any(
                row["stage17_directional_alert"]
                for row in attested_ticks[WARMUP:]
            )
        )

    def test_manifest_validation_checks_repo_and_config_hashes(self):
        manifest = build_manifest(Path("."))
        old_repo = os.environ.get("GITHUB_REPOSITORY")
        old_sha = os.environ.get("GITHUB_SHA")
        try:
            os.environ["GITHUB_REPOSITORY"] = manifest["github_repository"]
            os.environ["GITHUB_SHA"] = manifest["github_sha"]
            validate_manifest(manifest)

            changed = json.loads(json.dumps(manifest))
            changed["config_sha256"]["nssf"] = "0" * 64
            with self.assertRaises(ValueError):
                validate_manifest(changed)
        finally:
            if old_repo is None:
                os.environ.pop("GITHUB_REPOSITORY", None)
            else:
                os.environ["GITHUB_REPOSITORY"] = old_repo
            if old_sha is None:
                os.environ.pop("GITHUB_SHA", None)
            else:
                os.environ["GITHUB_SHA"] = old_sha

    def test_capture_job_has_no_authority_private_key_dependency(self):
        import research.stage27_capture as module

        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage27_authority" not in name for name in imported)
        )
        self.assertTrue(
            all("stage27_attestation" not in name for name in imported)
        )
        self.assertNotIn("private_key", module.__dict__)


if __name__ == "__main__":
    unittest.main()
