"""Stage25 full multichannel witness invariants."""
from __future__ import annotations

import ast
import inspect
import json
import unittest

from research.stage25_capture import (
    WARMUP_TICKS,
    common_path_projection,
    projected_fields,
    witness_supported_projection,
)
from research.stage25_live_detect import detect


def _row(tick: int, trusted_obj: dict, consumer_obj: dict) -> dict:
    known = {
        item["nfInstanceId"].lower()
        for item in trusted_obj.get("nfInstances", [])
        if isinstance(item, dict)
        and item.get("nfType") == "NSSF"
        and isinstance(item.get("nfInstanceId"), str)
    }
    trusted = projected_fields(
        trusted_obj, wire_bytes=1, known_registration_ids=known
    )
    consumer = projected_fields(
        consumer_obj, wire_bytes=1, known_registration_ids=known
    )
    return {
        "seed": 99201,
        "tick": tick,
        "trusted_status": trusted["status"],
        "consumer_status": consumer["status"],
        "trusted_canonical_bytes": trusted["canonical_bytes"],
        "consumer_canonical_bytes": consumer["canonical_bytes"],
        "trusted_nssf_profiles": trusted["nssf_profiles"],
        "consumer_nssf_profiles": consumer["nssf_profiles"],
        "trusted_wire_bytes": trusted["wire_bytes"],
        "consumer_wire_bytes": consumer["wire_bytes"],
        "trusted_structure": trusted["structure"],
        "consumer_structure": consumer["structure"],
        "trusted_semantic": trusted["semantic"],
        "consumer_semantic": consumer["semantic"],
        "reference_scope": "stage25-test",
    }


def _clean():
    return {
        "nfInstances": [
            {
                "nfInstanceId": "11111111-1111-4111-8111-111111111111",
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
                "untrustedExtra": "ignored",
            },
            {
                "nfInstanceId": "22222222-2222-4222-8222-222222222222",
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            },
            {
                "nfInstanceId": "33333333-3333-4333-8333-333333333333",
                "nfType": "AUSF",
                "nfStatus": "REGISTERED",
            },
        ]
    }


class Stage25Tests(unittest.TestCase):
    def test_projection_keeps_only_witness_supported_nssf_facts(self):
        projected = witness_supported_projection(_clean())
        self.assertEqual(len(projected["nfInstances"]), 2)
        self.assertEqual(
            set(projected["nfInstances"][0]),
            {
                "nfInstanceId",
                "nfType",
                "nfStatus",
                "nfRegisteredAtSource",
            },
        )
        self.assertTrue(
            all(x["nfType"] == "NSSF" for x in projected["nfInstances"])
        )

    def test_clean_projection_pairs_exactly_for_all_channels(self):
        row = _row(0, _clean(), _clean())
        self.assertEqual(
            row["trusted_canonical_bytes"],
            row["consumer_canonical_bytes"],
        )
        self.assertEqual(
            row["trusted_structure"],
            row["consumer_structure"],
        )
        self.assertEqual(
            row["trusted_semantic"],
            row["consumer_semantic"],
        )

    def test_profile_drop_is_visible_to_numeric_and_structural_projection(self):
        changed = _clean()
        changed = json.loads(json.dumps(changed))
        changed["nfInstances"] = changed["nfInstances"][1:]
        row = _row(WARMUP_TICKS, _clean(), changed)
        self.assertNotEqual(
            row["trusted_canonical_bytes"],
            row["consumer_canonical_bytes"],
        )
        self.assertNotEqual(
            row["trusted_structure"],
            row["consumer_structure"],
        )

    def test_status_substitution_preserves_structure_but_changes_semantics(self):
        changed = json.loads(json.dumps(_clean()))
        changed["nfInstances"][0]["nfStatus"] = "SUSPENDED"
        row = _row(WARMUP_TICKS, _clean(), changed)
        self.assertEqual(
            row["trusted_structure"],
            row["consumer_structure"],
        )
        self.assertNotEqual(
            row["trusted_semantic"],
            row["consumer_semantic"],
        )

    def test_frozen_detector_uses_all_gated_channels_under_exact_warmup(self):
        clean = _clean()
        dropped = json.loads(json.dumps(clean))
        dropped["nfInstances"] = dropped["nfInstances"][1:]
        suspended = json.loads(json.dumps(clean))
        suspended["nfInstances"][0]["nfStatus"] = "SUSPENDED"

        rows = []
        total = WARMUP_TICKS + 40
        for tick in range(total):
            consumer = clean
            if tick in (30, 34, 38):
                consumer = dropped
            if tick in (46, 50, 54):
                consumer = suspended
            rows.append(_row(tick, clean, consumer))

        common = [common_path_projection(row) for row in rows]
        result = detect(rows, common)

        cal = result["external_channel_calibration"]
        self.assertTrue(cal["sparse_quorum_enabled"])
        self.assertTrue(cal["structural_channel_enabled"])
        self.assertTrue(cal["semantic_channel_enabled"])
        self.assertEqual(cal["structural_exact_fraction"], 1.0)

        ext = result["external_reference"]["ticks"]
        self.assertTrue(
            any(row["stage20_structural_alert"] for row in ext[30:42])
        )
        self.assertTrue(
            any(row["stage21_semantic_alert"] for row in ext[46:58])
        )
        self.assertFalse(
            any(
                row["stage21_combined_alert"]
                for row in result["common_path_control"]["ticks"]
            )
        )

    def test_blind_detector_does_not_import_capture_or_labels(self):
        import research.stage25_live_detect as module

        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage25_capture" not in name for name in imported)
        )
        self.assertNotIn("labels_from_native_nrf_log", module.__dict__)


if __name__ == "__main__":
    unittest.main()
