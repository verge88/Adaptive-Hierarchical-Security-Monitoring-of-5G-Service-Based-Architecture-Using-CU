"""Stage21 frozen live protocol invariants."""
import ast
import inspect
import unittest

from research.stage21_live_detect import (
    FROZEN_STAGE21,
    WARMUP_TICKS,
)
from research.stage21_semantic import (
    SemanticQuorumState,
    semantic_projection,
)


class Stage21FrozenLiveTests(unittest.TestCase):
    def test_frozen_config_matches_successful_development(self):
        self.assertEqual(
            FROZEN_STAGE21.paired_agreement_threshold, 0.98
        )
        self.assertEqual(
            FROZEN_STAGE21.temporal_stability_threshold, 0.90
        )
        self.assertEqual(FROZEN_STAGE21.window_ticks, 16)
        self.assertEqual(FROZEN_STAGE21.required_hits, 3)
        self.assertEqual(
            FROZEN_STAGE21.min_mismatched_paths, 1
        )
        self.assertEqual(
            FROZEN_STAGE21.large_mismatched_paths, 3
        )
        self.assertEqual(
            FROZEN_STAGE21.recovery_clean_ticks, 2
        )

    def test_live_warmup_is_frozen(self):
        self.assertEqual(WARMUP_TICKS, 30)

    def test_detector_does_not_import_private_generator(self):
        import research.stage21_live_detect as module
        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(
                    alias.name for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage21_gateway" not in name for name in imported)
        )
        self.assertNotIn("build_private_schedule", module.__dict__)
        self.assertNotIn("ATTACK_KINDS", module.__dict__)

    def test_same_signature_reaches_quorum(self):
        clean = {
            "a": "stable",
            "b": 1,
        }
        warmup = [
            (
                semantic_projection(clean),
                semantic_projection(clean),
            )
            for _ in range(30)
        ]
        state = SemanticQuorumState(
            warmup, FROZEN_STAGE21
        )
        changed = {
            "a": "altered",
            "b": 1,
        }
        alerts = [
            state.observe(
                semantic_projection(clean),
                semantic_projection(changed),
            )["alert"]
            for _ in range(3)
        ]
        self.assertEqual(alerts, [False, False, True])

    def test_different_signatures_do_not_share_quorum(self):
        clean = {"a": "stable"}
        warmup = [
            (
                semantic_projection(clean),
                semantic_projection(clean),
            )
            for _ in range(30)
        ]
        state = SemanticQuorumState(
            warmup, FROZEN_STAGE21
        )
        alerts = []
        for value in ("x", "y", "z"):
            alerts.append(
                state.observe(
                    semantic_projection(clean),
                    semantic_projection({"a": value}),
                )["alert"]
            )
        self.assertEqual(alerts, [False, False, False])


if __name__ == "__main__":
    unittest.main()
