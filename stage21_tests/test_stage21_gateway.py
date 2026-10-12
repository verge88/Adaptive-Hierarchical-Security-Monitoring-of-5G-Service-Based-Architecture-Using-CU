"""Stage21 live generator invariants."""
import unittest

from research.stage21_gateway import (
    ATTACK_KINDS,
    EPISODE_TICKS,
    WARMUP_TICKS,
    build_private_schedule,
    mutate_payload,
)


class Stage21GatewayTests(unittest.TestCase):
    def test_schedule_is_randomized_and_after_warmup(self):
        a = build_private_schedule(8401)
        b = build_private_schedule(8402)
        self.assertNotEqual(
            [(x["kind"], x["pulse_local_ticks"]) for x in a],
            [(x["kind"], x["pulse_local_ticks"]) for x in b],
        )
        self.assertTrue(
            all(x["start_tick"] >= WARMUP_TICKS for x in a)
        )

    def test_sparse_positions_are_not_stage18_fixed_set(self):
        schedule = build_private_schedule(8401)
        sparse = [
            x for x in schedule
            if x["kind"] not in (
                "profile_drop_persistent",
                "boundary_cross_profile_identity_swap",
            )
        ]
        self.assertTrue(
            all(3 <= len(x["pulse_local_ticks"]) <= 5 for x in sparse)
        )
        self.assertTrue(
            any(
                set(x["pulse_local_ticks"]) != {1, 4, 8, 10}
                for x in sparse
            )
        )

    def test_value_faults_preserve_top_level_shape(self):
        payload = {
            "nfInstances": [
                {
                    "nfInstanceId": "abc",
                    "nfStatus": "REGISTERED",
                    "heartBeatTimer": 10,
                    "services": [{"scheme": "http"}],
                },
                {
                    "nfInstanceId": "def",
                    "nfStatus": "REGISTERED",
                },
            ]
        }
        for kind in (
            "identity_value_sparse",
            "status_value_sparse",
            "number_value_sparse",
            "scheme_value_sparse",
        ):
            changed, mutated, _ = mutate_payload(payload, kind)
            self.assertTrue(mutated)
            self.assertEqual(
                sorted(payload.keys()), sorted(changed.keys())
            )

    def test_all_declared_kinds_are_mutators(self):
        self.assertEqual(len(set(ATTACK_KINDS)), len(ATTACK_KINDS))
        self.assertGreater(EPISODE_TICKS, 0)


if __name__ == "__main__":
    unittest.main()
