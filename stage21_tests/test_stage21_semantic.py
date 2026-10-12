"""Stage 21 semantic integrity development invariants."""
import copy
import unittest

from research.stage21_develop import (
    SemanticWorld,
    apply_fault,
    base_payload,
)
from research.stage21_semantic import (
    SemanticQuorumConfig,
    SemanticQuorumState,
    semantic_projection,
)


class Stage21SemanticTests(unittest.TestCase):
    def test_value_change_keeps_structure_but_changes_semantics(self):
        base = base_payload(0)
        changed = apply_fault(
            base, "sparse_stable_string_change"
        )
        self.assertEqual(
            sorted(base.keys()),
            sorted(changed.keys()),
        )
        self.assertNotEqual(
            semantic_projection(base),
            semantic_projection(changed),
        )

    def test_dynamic_paths_are_excluded_by_temporal_stability(self):
        pairs = []
        for tick in range(30):
            trusted = base_payload(tick)
            consumer = copy.deepcopy(trusted)
            consumer["serverTick"] = tick + 1
            pairs.append(
                (
                    semantic_projection(trusted),
                    semantic_projection(consumer),
                )
            )
        config = SemanticQuorumConfig(
            paired_agreement_threshold=0.98,
            temporal_stability_threshold=0.90,
            window_ticks=12,
            required_hits=3,
            min_mismatched_paths=1,
            large_mismatched_paths=5,
            recovery_clean_ticks=2,
        )
        state = SemanticQuorumState(pairs, config)
        self.assertTrue(state.enabled)
        self.assertTrue(
            all("serverTick" not in path for path in state.selected_paths)
        )

    def test_cross_profile_identity_swap_is_boundary(self):
        base = base_payload(0)
        swapped = apply_fault(base, "cross_profile_identity_swap")
        self.assertEqual(
            semantic_projection(base),
            semantic_projection(swapped),
        )

    def test_world_schedule_is_after_warmup(self):
        world = SemanticWorld(24001)
        self.assertTrue(
            all(episode.start >= 30 for episode in world.episodes)
        )


if __name__ == "__main__":
    unittest.main()
