"""Stage-19 frozen live protocol invariants."""
import ast
import inspect
import unittest

from research.stage19_live_detect import (
    FROZEN_STAGE19,
    WARMUP_TICKS,
)
from research.stage19_detector import (
    StabilityGatedQuorumState,
)


class Stage19FrozenLiveTests(unittest.TestCase):
    def test_frozen_config_matches_conservative_development(self):
        self.assertEqual(
            FROZEN_STAGE19.stability_fraction_threshold,
            0.90,
        )
        self.assertEqual(FROZEN_STAGE19.zero_epsilon, 1e-12)
        self.assertEqual(FROZEN_STAGE19.window_ticks, 16)
        self.assertEqual(FROZEN_STAGE19.required_hits, 2)
        self.assertEqual(FROZEN_STAGE19.mismatch_epsilon, 0.020)

    def test_live_warmup_is_frozen(self):
        self.assertEqual(WARMUP_TICKS, 30)

    def test_live_detector_does_not_import_private_labels(self):
        import research.stage19_live_detect as module

        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage18_gateway" not in name for name in imported)
        )
        self.assertNotIn("build_private_schedule", module.__dict__)
        self.assertNotIn("ATTACK_KINDS", module.__dict__)

    def test_noisy_calibration_disables_quorum(self):
        calibration = [
            (index - 15) / 1000
            for index in range(30)
        ]
        state = StabilityGatedQuorumState(
            calibration,
            FROZEN_STAGE19,
        )
        self.assertFalse(state.quorum_enabled)

    def test_structurally_stable_calibration_enables_quorum(self):
        calibration = [0.0] * 29 + [0.001]
        state = StabilityGatedQuorumState(
            calibration,
            FROZEN_STAGE19,
        )
        self.assertTrue(state.quorum_enabled)


if __name__ == "__main__":
    unittest.main()
