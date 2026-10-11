"""Frozen Stage-17 final-protocol invariants."""
import unittest

from research.stage17_final import (
    FINAL_SEEDS,
    FINAL_START_SEED,
    FROZEN_DIRECTIONAL,
    FROZEN_PAGE_HINKLEY,
)


class Stage17FrozenProtocolTests(unittest.TestCase):
    def test_final_block_is_exactly_predeclared(self):
        self.assertEqual(FINAL_START_SEED, 7001)
        self.assertEqual(FINAL_SEEDS, 200)

    def test_directional_config_is_frozen_from_development(self):
        self.assertEqual(FROZEN_DIRECTIONAL.decay, 0.90)
        self.assertEqual(FROZEN_DIRECTIONAL.reference, 0.12)
        self.assertEqual(FROZEN_DIRECTIONAL.threshold, 5.0)
        self.assertEqual(
            FROZEN_DIRECTIONAL.direction_gate_p,
            0.06,
        )

    def test_page_hinkley_config_is_frozen_from_development(self):
        self.assertEqual(FROZEN_PAGE_HINKLEY.delta, 0.50)
        self.assertEqual(FROZEN_PAGE_HINKLEY.threshold, 8.0)
        self.assertEqual(
            FROZEN_PAGE_HINKLEY.integrity_gate_p,
            0.08,
        )
        self.assertEqual(
            FROZEN_PAGE_HINKLEY.mean_alpha,
            0.10,
        )


if __name__ == "__main__":
    unittest.main()
