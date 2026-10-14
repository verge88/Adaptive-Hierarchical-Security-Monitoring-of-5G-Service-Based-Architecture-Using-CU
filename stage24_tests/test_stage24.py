"""Stage24 native-NRF compromise / NF-side witness invariants."""
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
from research.stage24_capture import (
    TOTAL_TICKS,
    WARMUP_TICKS,
    common_path_projection,
    expected_episodes,
    labels_from_native_nrf_log,
    latest_nf_registration_id,
)
from research.stage24_live_detect import detect


IDS = (
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
)


def _consumer(kind: str | None = None):
    profiles = [
        {
            "nfInstanceId": IDS[0],
            "nfType": "NSSF",
            "nfStatus": "REGISTERED",
            "heartBeatTimer": 10,
            "fqdn": "nssf",
        },
        {
            "nfInstanceId": IDS[1],
            "nfType": "NSSF",
            "nfStatus": "REGISTERED",
            "heartBeatTimer": 10,
            "fqdn": "nssf2",
        },
    ]
    if kind == "status_substitution":
        profiles[0]["nfStatus"] = "SUSPENDED"
    elif kind == "profile_drop":
        profiles.pop()
    return {"validityPeriod": 10, "nfInstances": profiles}


def _witness():
    return {
        "nfInstances": [
            {
                "nfInstanceId": IDS[0],
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            },
            {
                "nfInstanceId": IDS[1],
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            },
        ]
    }


def _row(tick: int, kind: str | None = None):
    consumer_obj = _consumer(kind)
    witness_obj = _witness()
    consumer_semantic = serialize_projection(
        semantic_projection(consumer_obj)
    )
    consumer_structure = serialize_counter(
        structural_counter(consumer_obj)
    )
    size = len(
        json.dumps(
            consumer_obj,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf8")
    )
    return {
        "seed": 99101,
        "tick": tick,
        "trusted_status": 200,
        "consumer_status": 200,
        "trusted_canonical_bytes": size,
        "consumer_canonical_bytes": size,
        "trusted_nssf_profiles": 2,
        "consumer_nssf_profiles": len(
            consumer_obj["nfInstances"]
        ),
        "trusted_wire_bytes": 1,
        "consumer_wire_bytes": 1,
        "trusted_structure": consumer_structure,
        "consumer_structure": consumer_structure,
        "trusted_semantic": serialize_projection(
            semantic_projection(witness_obj)
        ),
        "consumer_semantic": consumer_semantic,
        "reference_scope": "nf_side_witness",
    }


class Stage24Tests(unittest.TestCase):
    def test_nf_side_registration_id_parser(self):
        log = (
            "10/14 10:00:00.000: [sbi] INFO: "
            "[11111111-1111-4111-8111-111111111111] "
            "NF registered [Heartbeat:10s]\n"
        )
        self.assertEqual(
            latest_nf_registration_id(log), IDS[0]
        )

    def test_native_nrf_log_is_authoritative_private_schedule(self):
        lines = []
        for episode in expected_episodes():
            for tick in episode["mutation_ticks"]:
                lines.append(
                    "nrf | STAGE24_NATIVE_NRF_LAB_MUTATION "
                    f"eligible={tick + 1} kind={episode['kind']}"
                )
        labels = labels_from_native_nrf_log(
            9101, "\n".join(lines)
        )
        self.assertEqual(
            labels["native_nrf_inprocess_log_marker_count"], 18
        )
        self.assertEqual(labels["total_ticks"], TOTAL_TICKS)

    def test_frozen_semantic_detector_detects_both_nrf_fault_families(self):
        mutation_by_tick = {}
        for episode in expected_episodes():
            for tick in episode["mutation_ticks"]:
                mutation_by_tick[tick] = episode["kind"]

        external = [
            _row(tick, mutation_by_tick.get(tick))
            for tick in range(TOTAL_TICKS)
        ]
        common = [
            common_path_projection(row)
            for row in external
        ]
        result = detect(external, common)

        ext = result["external_reference"]
        common_result = result["common_path_control"]
        self.assertTrue(
            ext["calibration"]["semantic_channel_enabled"]
        )
        selected = set(
            ext["calibration"]["semantic_selected_paths"]
        )
        self.assertIn(
            "$/nfInstances[]/nfStatus:string", selected
        )
        self.assertIn(
            "$/nfInstances[]/nfInstanceId:string", selected
        )

        for episode in expected_episodes():
            start = episode["start_tick"]
            end = episode["end_tick"]
            self.assertTrue(
                any(
                    row["stage21_combined_alert"]
                    for row in ext["ticks"][start:end]
                ),
                episode["kind"],
            )

        self.assertFalse(
            any(
                row["stage21_combined_alert"]
                for row in common_result["ticks"][WARMUP_TICKS:]
            )
        )

    def test_numeric_and_structure_channels_are_neutralized(self):
        row = _row(WARMUP_TICKS, "profile_drop")
        self.assertEqual(
            row["trusted_canonical_bytes"],
            row["consumer_canonical_bytes"],
        )
        self.assertEqual(
            row["trusted_structure"],
            row["consumer_structure"],
        )

    def test_blind_detector_does_not_import_capture_or_labels(self):
        import research.stage24_live_detect as module

        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage24_capture" not in name for name in imported)
        )
        self.assertNotIn("expected_episodes", module.__dict__)

    def test_instrumented_nrf_source_mutates_before_stock_send(self):
        text = Path("live/stage24-nnrf-handler.c").read_text(
            encoding="utf8"
        )
        function = text.index("bool nrf_nnrf_handle_nf_discover(")
        marker = text.index(
            "stage24_lab_instrument_discovery_response(response);",
            function,
        )
        send = text.index(
            "ogs_sbi_server_send_response(stream, response)",
            marker,
        )
        self.assertLess(marker, send)
        self.assertIn(
            "STAGE24_NATIVE_NRF_LAB_MUTATION", text
        )
        self.assertIn(
            "#define STAGE24_ENABLE_PATH", text
        )


if __name__ == "__main__":
    unittest.main()
