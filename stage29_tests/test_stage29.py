"""Stage29 held-out attested-invariant tests."""
from __future__ import annotations

import ast
import inspect
import json
import unittest

from research.stage27_attestation import project
from research.stage27_authority import build_manifest
from research.stage29_live_detect import (
    attested_invariant_mismatch,
    detect,
)
from pathlib import Path


WARMUP = 30


def raw_rows(single_attack_tick: int | None) -> list[dict]:
    rows = []
    for tick in range(WARMUP + 8):
        count = 3 if tick == single_attack_tick else 2
        rows.append(
            {
                "seed": 99601,
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


class Stage29Tests(unittest.TestCase):
    def test_one_sample_verified_mismatch_alerts_without_threshold(self):
        manifest = build_manifest(Path("."))
        attested, compromised = project(
            raw_rows(WARMUP), manifest
        )
        for row in attested:
            row["stage29_attestation_verified_reference"] = True
        for row in compromised:
            row["stage29_attestation_verified_reference"] = False

        self.assertFalse(
            attested_invariant_mismatch(attested[WARMUP - 1])
        )
        self.assertTrue(
            attested_invariant_mismatch(attested[WARMUP])
        )
        self.assertFalse(
            attested_invariant_mismatch(compromised[WARMUP])
        )

    def test_augmented_catches_short_attack_missed_by_frozen_stack(self):
        manifest = build_manifest(Path("."))
        attested, compromised = project(
            raw_rows(WARMUP), manifest
        )
        for row in attested:
            row["stage29_attestation_verified_reference"] = True
        for row in compromised:
            row["stage29_attestation_verified_reference"] = False

        result = detect(attested, compromised)
        ext = result["external_reference"]["ticks"]
        pair = result["common_path_control"]["ticks"]

        self.assertFalse(ext[WARMUP]["stage21_combined_alert"])
        self.assertTrue(
            ext[WARMUP]["stage29_attested_invariant_alert"]
        )
        self.assertTrue(ext[WARMUP]["stage29_augmented_alert"])
        self.assertFalse(
            any(row["stage29_augmented_alert"] for row in pair)
        )

    def test_clean_stream_has_no_attested_invariant_alert(self):
        manifest = build_manifest(Path("."))
        attested, compromised = project(raw_rows(None), manifest)
        for row in attested:
            row["stage29_attestation_verified_reference"] = True
        for row in compromised:
            row["stage29_attestation_verified_reference"] = False

        result = detect(attested, compromised)
        self.assertFalse(
            any(
                row["stage29_attested_invariant_alert"]
                for row in result["external_reference"]["ticks"]
            )
        )

    def test_blind_detector_imports_no_capture_or_private_schedule(self):
        import research.stage29_live_detect as module

        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage29_capture" not in name for name in imported)
        )
        self.assertTrue(
            all("stage28_capture" not in name for name in imported)
        )
        self.assertNotIn("build_private_schedule", module.__dict__)

    def test_rule_is_exact_discrete_mismatch_not_numeric_threshold(self):
        source = inspect.getsource(attested_invariant_mismatch)
        self.assertIn("trusted_nssf_profiles", source)
        self.assertIn("trusted_semantic", source)
        self.assertNotIn("threshold", source.lower())


if __name__ == "__main__":
    unittest.main()
