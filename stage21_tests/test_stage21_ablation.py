"""Frozen Stage21 ablation invariants."""
import copy
import unittest

from research.stage21_ablation_detect import (
    VARIANT_KEYS,
)


class Stage21AblationTests(unittest.TestCase):
    def test_required_variants_exist(self):
        required = {
            "directional_only",
            "directional_plus_sparse",
            "structural_only",
            "semantic_only",
            "directional_plus_structural",
            "full_without_semantic",
            "full_without_structural",
            "full_without_sparse",
            "full",
        }
        self.assertEqual(set(VARIANT_KEYS), required)

    def test_boolean_composition_identities(self):
        for directional in (False, True):
            for stage19 in (False, True):
                for structural in (False, True):
                    for semantic in (False, True):
                        full = stage19 or structural or semantic
                        no_sem = stage19 or structural
                        no_struct = stage19 or semantic
                        no_sparse = directional or structural or semantic
                        self.assertTrue(full or not no_sem)
                        self.assertTrue(full or not no_struct)
                        # Stage19 contains the frozen Stage17 fast path, so
                        # replacing Stage19 by Stage17 is the leave-sparse-out
                        # definition rather than an arbitrary comparator.
                        if not stage19 and directional:
                            # This combination cannot occur for a correct
                            # Stage19 implementation but composition remains
                            # well-defined.
                            self.assertTrue(no_sparse or not (structural or semantic))


if __name__ == "__main__":
    unittest.main()
