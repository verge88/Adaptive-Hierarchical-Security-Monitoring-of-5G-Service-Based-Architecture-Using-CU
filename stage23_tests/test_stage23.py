"""Stage23 native-SCP in-process experiment invariants."""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import unittest

from research.stage20_structure import (
    serialize_counter,
    structural_counter,
)
from research.stage21_semantic import (
    semantic_projection,
    serialize_projection,
)
from research.stage23_capture import (
    EXPECTED_MUTATION_TICKS,
    TOTAL_TICKS,
    WARMUP_TICKS,
    common_path_projection,
    labels_from_native_scp_log,
)
from research.stage23_live_detect import detect


def _size(obj):
    return len(
        json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf8")
    )


def _row(tick, trusted_obj, consumer_obj):
    return {
        "seed": 99001,
        "tick": tick,
        "trusted_status": 200,
        "consumer_status": 200,
        "trusted_canonical_bytes": _size(trusted_obj),
        "consumer_canonical_bytes": _size(consumer_obj),
        "trusted_nssf_profiles": len(
            trusted_obj.get("nfInstances", [])
        ),
        "consumer_nssf_profiles": len(
            consumer_obj.get("nfInstances", [])
        ),
        "trusted_wire_bytes": 1,
        "consumer_wire_bytes": 1,
        "trusted_structure": serialize_counter(
            structural_counter(trusted_obj)
        ),
        "consumer_structure": serialize_counter(
            structural_counter(consumer_obj)
        ),
        "trusted_semantic": serialize_projection(
            semantic_projection(trusted_obj)
        ),
        "consumer_semantic": serialize_projection(
            semantic_projection(consumer_obj)
        ),
        "reference_scope": "direct_native_nrf_bypasses_native_scp",
    }


class Stage23Tests(unittest.TestCase):
    def test_native_log_is_authoritative_private_schedule(self):
        log = "\n".join(
            "scp | STAGE23_NATIVE_SCP_LAB_MUTATION "
            f"eligible={tick + 1}"
            for tick in EXPECTED_MUTATION_TICKS
        )
        labels = labels_from_native_scp_log(9001, log)
        self.assertEqual(
            labels["native_scp_log_mutation_ticks"],
            list(EXPECTED_MUTATION_TICKS),
        )
        self.assertEqual(labels["total_ticks"], TOTAL_TICKS)
        self.assertEqual(
            labels["native_scp_inprocess_log_marker_count"], 18
        )

    def test_common_path_projection_erases_pairwise_difference(self):
        trusted = {
            "nfInstances": [
                {
                    "nfInstanceId": "a",
                    "nfStatus": "REGISTERED",
                }
            ]
        }
        changed = {
            "nfInstances": [
                {
                    "nfInstanceId": "a",
                    "nfStatus": "SUSPENDED",
                }
            ]
        }
        projected = common_path_projection(
            _row(WARMUP_TICKS, trusted, changed)
        )
        self.assertEqual(
            projected["trusted_semantic"],
            projected["consumer_semantic"],
        )
        self.assertEqual(
            projected["trusted_canonical_bytes"],
            projected["consumer_canonical_bytes"],
        )

    def test_frozen_detector_detects_repeated_status_change(self):
        clean = {
            "nfInstances": [
                {
                    "nfInstanceId": "a",
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                },
                {
                    "nfInstanceId": "b",
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                },
            ]
        }
        changed = {
            "nfInstances": [
                {
                    "nfInstanceId": "a",
                    "nfType": "NSSF",
                    "nfStatus": "SUSPENDED",
                },
                {
                    "nfInstanceId": "b",
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                },
            ]
        }

        external = []
        for tick in range(TOTAL_TICKS):
            consumer = (
                changed if tick in EXPECTED_MUTATION_TICKS else clean
            )
            external.append(_row(tick, clean, consumer))
        common = [common_path_projection(row) for row in external]

        result = detect(external, common)
        ext = result["external_reference"]["ticks"]
        common_ticks = result["common_path_control"]["ticks"]

        self.assertTrue(
            any(
                row["stage21_combined_alert"]
                for row in ext[WARMUP_TICKS:]
            )
        )
        self.assertFalse(
            any(row["stage21_combined_alert"] for row in common_ticks)
        )

    def test_blind_detector_has_no_private_label_import(self):
        import research.stage23_live_detect as module

        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage23_capture" not in name for name in imported)
        )
        self.assertNotIn("EXPECTED_MUTATION_TICKS", module.__dict__)

    def test_instrumented_source_mutates_before_stock_send(self):
        text = Path("live/stage23-sbi-path.c").read_text(encoding="utf8")
        marker = text.index("stage23_lab_instrument_response(response);")
        send = text.index(
            "ogs_sbi_server_send_response(stream, response)",
            marker,
        )
        self.assertLess(marker, send)
        self.assertIn(
            "STAGE23_NATIVE_SCP_LAB_MUTATION",
            text,
        )
        self.assertNotIn("socket(", text[0:marker])


if __name__ == "__main__":
    unittest.main()
