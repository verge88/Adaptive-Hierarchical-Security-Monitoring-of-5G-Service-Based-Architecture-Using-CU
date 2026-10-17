import unittest
from statistical_reanalysis import exact_interval, scenario_row, summarize


class StatisticsTests(unittest.TestCase):
    def test_exact_boundaries(self):
        self.assertAlmostEqual(exact_interval(256, 256)[0], 0.025**(1/256))
        self.assertAlmostEqual(exact_interval(0, 256)[1], 1-0.025**(1/256))
        self.assertAlmostEqual(exact_interval(1, 2)[0], 0.012579117093425)
        self.assertAlmostEqual(exact_interval(1, 2)[1], 0.987420882906575)

    def test_partial_simultaneous_detection_fails_scenario(self):
        lab = dict(seed=1, challenge_nonce='a', topology_template_id=0,
                   attack_entries=[dict(tick=0,target_nf_type=t) for t in ('A','B')])
        signed = {'verdict': dict(seed=1, challenge_nonce='a', alerts=[
            dict(tick=0, relational_alert=True, relational_alert_by_nf_type={'A':True,'B':False}),
            dict(tick=1, relational_alert=False)])}
        row = scenario_row(lab, signed)
        self.assertEqual(row['recall'], .5)
        self.assertEqual(row['all_attacks_detected'], 0)
        self.assertEqual(row['clean_scenario'], 1)
        signed['verdict']['alerts'][1]['relational_alert'] = True
        self.assertEqual(scenario_row(lab,signed)['clean_scenario'],0)

    def test_scenarios_not_attacks_are_units(self):
        rows = [dict(recall=1, all_attacks_detected=1, clean_scenario=1,joint_success=1,attacks=n) for n in (1,1000)]
        self.assertEqual(summarize(rows)['scenarios'],2)
        self.assertLess(summarize(rows)['independent_scenarios_hoeffding95'][0],1)


if __name__ == '__main__':
    unittest.main()
