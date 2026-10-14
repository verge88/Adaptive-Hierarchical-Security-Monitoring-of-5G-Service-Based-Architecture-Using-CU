"""Stage26 persistent directional attack invariants."""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import unittest

from research.stage25_capture import (
    common_path_projection,
    projected_fields,
)
from research.stage26_capture import (
    ATTACK_KIND,
    EPISODE_TICKS,
    WARMUP_TICKS,
)
from research.stage26_live_detect import detect


def clean_obj():
    return {
        "nfInstances": [
            {
                "nfInstanceId": "11111111-1111-4111-8111-111111111111",
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            },
            {
                "nfInstanceId": "22222222-2222-4222-8222-222222222222",
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            },
        ]
    }


def phantom_obj():
    obj = json.loads(json.dumps(clean_obj()))
    obj["nfInstances"].append(
        {
            "nfInstanceId": "26000000-0000-4000-8000-000000000026",
            "nfType": "NSSF",
            "nfStatus": "REGISTERED",
        }
    )
    return obj


def row(tick: int, consumer_obj: dict) -> dict:
    trusted_obj = clean_obj()
    known = {
        item["nfInstanceId"].lower()
        for item in trusted_obj["nfInstances"]
    }
    trusted = projected_fields(
        trusted_obj,
        wire_bytes=1,
        known_registration_ids=known,
    )
    consumer = projected_fields(
        consumer_obj,
        wire_bytes=1,
        known_registration_ids=known,
    )
    return {
        "seed": 99301,
        "tick": tick,
        "trusted_status": 200,
        "consumer_status": 200,
        "trusted_canonical_bytes": trusted["canonical_bytes"],
        "consumer_canonical_bytes": consumer["canonical_bytes"],
        "trusted_nssf_profiles": trusted["nssf_profiles"],
        "consumer_nssf_profiles": consumer["nssf_profiles"],
        "trusted_wire_bytes": 1,
        "consumer_wire_bytes": 1,
        "trusted_structure": trusted["structure"],
        "consumer_structure": consumer["structure"],
        "trusted_semantic": trusted["semantic"],
        "consumer_semantic": consumer["semantic"],
        "reference_scope": "stage26-test",
    }


class Stage26Tests(unittest.TestCase):
    def test_persistent_phantom_creates_positive_canonical_shift(self):
        r = row(WARMUP_TICKS, phantom_obj())
        self.assertGreater(
            r["consumer_canonical_bytes"],
            r["trusted_canonical_bytes"],
        )

    def test_frozen_directional_detector_alerts_within_episode(self):
        rows = []
        total = WARMUP_TICKS + EPISODE_TICKS + 4
        for tick in range(total):
            consumer = (
                phantom_obj()
                if WARMUP_TICKS <= tick < WARMUP_TICKS + EPISODE_TICKS
                else clean_obj()
            )
            rows.append(row(tick, consumer))
        common = [common_path_projection(item) for item in rows]

        result = detect(rows, common)
        ext = result["external_reference"]["ticks"]
        attack = ext[WARMUP_TICKS:WARMUP_TICKS + EPISODE_TICKS]
        self.assertTrue(
            any(item["stage17_directional_alert"] for item in attack)
        )
        self.assertFalse(
            any(
                item["stage17_directional_alert"]
                for item in result["common_path_control"]["ticks"]
            )
        )

    def test_native_source_has_local_only_persistent_hook(self):
        text = Path("live/stage26-nnrf-handler.c").read_text(encoding="utf8")
        self.assertIn("STAGE26_NATIVE_NRF_LAB_MUTATION", text)
        self.assertIn("/run/stage26/enabled", text)
        self.assertIn("phantom_profile_persistent", text)
        self.assertIn("local >= 12", text)
        self.assertNotIn("STAGE26_ENABLE_PORT", text)

    def test_blind_detector_imports_no_capture_labels(self):
        import research.stage26_live_detect as module

        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage26_capture" not in name for name in imported)
        )
        self.assertNotIn("ATTACK_KIND", module.__dict__)

    def test_attack_kind_is_frozen(self):
        self.assertEqual(ATTACK_KIND, "phantom_profile_persistent")


if __name__ == "__main__":
    unittest.main()
