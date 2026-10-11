"""Stage-20 frozen live protocol invariants."""
import ast
import inspect
import unittest

from research.stage20_live_detect import (
    FROZEN_STAGE20,
    WARMUP_TICKS,
)
from research.stage20_structure import (
    StructuralQuorumState,
    structural_counter,
    structural_difference,
)


class Stage20FrozenLiveTests(unittest.TestCase):
    def test_frozen_config_matches_conservative_development(self):
        self.assertEqual(
            FROZEN_STAGE20.stability_fraction_threshold,
            0.98,
        )
        self.assertEqual(FROZEN_STAGE20.window_ticks, 12)
        self.assertEqual(FROZEN_STAGE20.required_hits, 4)
        self.assertEqual(
            FROZEN_STAGE20.min_token_difference,
            1,
        )
        self.assertEqual(
            FROZEN_STAGE20.large_difference_tokens,
            8,
        )

    def test_live_warmup_is_frozen(self):
        self.assertEqual(WARMUP_TICKS, 30)

    def test_detector_does_not_import_fault_schedule(self):
        import research.stage20_live_detect as module

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
            all("stage18_gateway" not in name for name in imported)
        )
        self.assertNotIn("build_private_schedule", module.__dict__)
        self.assertNotIn("ATTACK_KINDS", module.__dict__)

    def test_structural_channel_disables_on_unstable_warmup(self):
        clean = structural_counter(
            {"a": 1, "b": {"x": True}}
        )
        changed = structural_counter(
            {"a": 1, "b": {"x": True}, "c": 3}
        )
        diffs = [
            structural_difference(
                clean,
                clean if index < 28 else changed,
            )
            for index in range(30)
        ]
        state = StructuralQuorumState(
            diffs,
            FROZEN_STAGE20,
        )
        self.assertFalse(state.enabled)

    def test_structural_channel_enables_on_exact_warmup(self):
        clean = structural_counter(
            {"a": 1, "b": {"x": True}}
        )
        diffs = [
            structural_difference(clean, clean)
            for _ in range(30)
        ]
        state = StructuralQuorumState(
            diffs,
            FROZEN_STAGE20,
        )
        self.assertTrue(state.enabled)


if __name__ == "__main__":
    unittest.main()
