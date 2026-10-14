"""Stage30 baseline freshness and legitimate-transition invariants."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path
import unittest

from research.stage30_attestation import (
    baseline_for_tick,
    candidate_is_fresh_for_tick,
    project,
    run_replay_audit,
)
from research.stage30_authority import (
    build_epoch_manifests,
    validate_static_chain,
)
from research.stage30_capture import (
    ATTACK_START_TICK,
    LEGITIMATE_TRANSITION_WINDOW,
    expected_epoch_for_tick,
    expected_state_for_tick,
    shift_private_schedule,
)
from research.stage28_capture import build_private_schedule
from research.stage30_live_detect import detect


def synthetic_raw(with_attack: bool) -> list[dict]:
    rows = []
    for tick in range(70):
        expected_count, expected_registered = expected_state_for_tick(tick)
        count = expected_count
        registered = expected_registered
        if with_attack and tick == 55:
            count += 1
            registered += 1
        rows.append(
            {
                "seed": 99701,
                "tick": tick,
                "witness_first": tick % 2 == 0,
                "baseline_epoch": expected_epoch_for_tick(tick),
                "consumer_nssf_count": count,
                "consumer_registered_count": registered,
                "compromised_witness_nssf_count": count,
                "compromised_witness_registered_count": registered,
                "common_source_equal": True,
            }
        )
    return rows


class Stage30Tests(unittest.TestCase):
    def test_authority_chain_is_contiguous_and_hash_linked(self):
        manifests = build_epoch_manifests(Path("."))
        validate_static_chain(manifests)
        self.assertEqual([m["epoch"] for m in manifests], [0, 1, 2, 3])
        self.assertEqual(
            [m["valid_from_tick"] for m in manifests],
            [0, 30, 40, 45],
        )

    def test_previous_epochs_are_rejected_after_transition(self):
        manifests = build_epoch_manifests(Path("."))
        audit = run_replay_audit(manifests)
        self.assertGreater(audit["attempt_count"], 0)
        self.assertEqual(audit["accepted_count"], 0)
        self.assertFalse(candidate_is_fresh_for_tick(manifests[0], 30))
        self.assertFalse(candidate_is_fresh_for_tick(manifests[1], 40))
        self.assertFalse(candidate_is_fresh_for_tick(manifests[2], 45))

    def test_baseline_for_tick_selects_expected_epoch(self):
        manifests = build_epoch_manifests(Path("."))
        checks = {0: 0, 29: 0, 30: 1, 39: 1, 40: 2, 44: 2, 45: 3}
        for tick, epoch in checks.items():
            self.assertEqual(
                int(baseline_for_tick(manifests, tick)["epoch"]),
                epoch,
            )

    def test_shifted_attack_schedule_reserves_transition_window(self):
        shifted = shift_private_schedule(build_private_schedule())
        self.assertTrue(shifted["entries"])
        self.assertGreaterEqual(
            min(entry["tick"] for entry in shifted["entries"]),
            ATTACK_START_TICK,
        )
        transition = set(LEGITIMATE_TRANSITION_WINDOW)
        self.assertFalse(
            any(entry["tick"] in transition for entry in shifted["entries"])
        )

    def test_current_signed_epochs_do_not_alarm_on_legitimate_transitions(self):
        manifests = build_epoch_manifests(Path("."))
        attested, compromised = project(
            synthetic_raw(with_attack=False),
            manifests,
        )
        result = detect(attested, compromised)
        ext = result["external_reference"]["ticks"]
        for tick in LEGITIMATE_TRANSITION_WINDOW:
            self.assertFalse(ext[tick]["stage29_augmented_alert"])

    def test_stage29_rule_still_detects_post_transition_attack(self):
        manifests = build_epoch_manifests(Path("."))
        attested, compromised = project(
            synthetic_raw(with_attack=True),
            manifests,
        )
        result = detect(attested, compromised)
        self.assertTrue(
            result["external_reference"]["ticks"][55][
                "stage29_attested_invariant_alert"
            ]
        )
        self.assertTrue(
            result["external_reference"]["ticks"][55][
                "stage29_augmented_alert"
            ]
        )
        self.assertFalse(
            any(
                row["stage29_augmented_alert"]
                for row in result["common_path_control"]["ticks"]
            )
        )

    def test_blind_detector_imports_no_capture_or_private_schedule(self):
        import research.stage30_live_detect as module

        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage30_capture" not in name for name in imported)
        )
        self.assertTrue(
            all("stage28_capture" not in name for name in imported)
        )


if __name__ == "__main__":
    unittest.main()
