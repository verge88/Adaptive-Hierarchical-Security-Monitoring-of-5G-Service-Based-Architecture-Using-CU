"""Stage-20 structural integrity invariants."""
import copy
import unittest

from research.stage20_develop import (
    STRESS_SEEDS,
    STRESS_START,
    TUNE_SEEDS,
    TUNE_START,
    VALID_SEEDS,
    VALID_START,
    base_payload,
)
from research.stage20_structure import (
    StructuralQuorumConfig,
    StructuralQuorumState,
    structural_counter,
    structural_difference,
)


class Stage20StructureTests(unittest.TestCase):
    def test_scalar_value_changes_do_not_change_structure(self):
        a = base_payload()
        b = copy.deepcopy(a)
        b["validityPeriod"] = 999
        b["searchId"] = "different"
        b["nfInstances"][0]["priority"] = 42

        diff = structural_difference(
            structural_counter(a),
            structural_counter(b),
        )
        self.assertTrue(diff.exact_match)

    def test_single_leaf_deletion_is_detected(self):
        trusted = base_payload()
        consumer = copy.deepcopy(trusted)
        del consumer["nfInstances"][0]["services"][0]["scheme"]

        diff = structural_difference(
            structural_counter(trusted),
            structural_counter(consumer),
        )
        self.assertFalse(diff.exact_match)
        self.assertGreater(diff.missing_tokens, 0)
        self.assertEqual(diff.extra_tokens, 0)
        self.assertLess(diff.direction, 0)

    def test_array_multiplicity_is_preserved(self):
        trusted = base_payload()
        consumer = copy.deepcopy(trusted)
        consumer["nfInstances"].append(
            copy.deepcopy(consumer["nfInstances"][0])
        )
        diff = structural_difference(
            structural_counter(trusted),
            structural_counter(consumer),
        )
        self.assertGreater(diff.extra_tokens, 0)
        self.assertGreater(diff.direction, 0)

    def test_quorum_requires_current_structural_mismatch(self):
        clean = structural_difference(
            structural_counter(base_payload()),
            structural_counter(base_payload()),
        )
        altered = base_payload()
        del altered["validityPeriod"]
        mismatch = structural_difference(
            structural_counter(base_payload()),
            structural_counter(altered),
        )
        config = StructuralQuorumConfig(
            stability_fraction_threshold=0.90,
            window_ticks=16,
            required_hits=2,
            min_token_difference=1,
            large_difference_tokens=99,
        )
        state = StructuralQuorumState(
            [clean] * 30,
            config,
        )
        first = state.observe(mismatch)
        self.assertFalse(first["alert"])
        state.observe(clean)
        second = state.observe(mismatch)
        self.assertTrue(second["alert"])

    def test_development_blocks_exclude_previous_live_seeds(self):
        used = (
            set(range(TUNE_START, TUNE_START + TUNE_SEEDS))
            | set(range(VALID_START, VALID_START + VALID_SEEDS))
            | set(range(STRESS_START, STRESS_START + STRESS_SEEDS))
        )
        self.assertFalse(used & set(range(8101, 8107)))
        self.assertFalse(used & set(range(8201, 8207)))


if __name__ == "__main__":
    unittest.main()
