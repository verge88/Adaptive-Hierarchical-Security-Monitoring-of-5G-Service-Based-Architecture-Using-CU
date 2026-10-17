import copy
import unittest
from review_reanalysis import frozen_functions, semantic_policy_matches, add, matrix


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.ns=frozen_functions()
        self.pre={'profiles':{
            'a':{'nfType':'NSSF','ipv4Addresses':['127.0.0.12'],'nfServices':[]},
            'b':{'nfType':'NSSF','ipv4Addresses':['127.0.0.13'],'nfServices':[]}},'duplicateIds':[]}
        self.post=copy.deepcopy(self.pre)
        self.post['profiles']['c']=self.post['profiles'].pop('a')

    def alert(self, observed):
        return self.ns['type_transition_alert']('NSSF',observed,self.pre,self.post,'nssf1')

    def test_before_and_after_are_allowed(self):
        self.assertFalse(self.alert(self.pre))
        self.assertFalse(self.alert(self.post))

    def test_moving_absence_allowed_stable_absence_rejected(self):
        obs=copy.deepcopy(self.pre); del obs['profiles']['a']
        self.assertFalse(self.alert(obs))
        obs=copy.deepcopy(self.pre); del obs['profiles']['b']
        self.assertTrue(self.alert(obs))

    def test_unknown_uuid_and_service_and_extra_address_rejected(self):
        for field,value in [('nfServices',[{'serviceName':'extra'}]),('ipv4Addresses',['127.0.0.12','192.0.2.1'])]:
            obs=copy.deepcopy(self.pre); obs['profiles']['a'][field]=value
            self.assertTrue(self.alert(obs))
        obs=copy.deepcopy(self.pre); obs['profiles']['z']=obs['profiles'].pop('a')
        self.assertTrue(self.alert(obs))

    def test_ambiguous_endpoint_rejected(self):
        obs=copy.deepcopy(self.pre); obs['profiles']['z']=copy.deepcopy(obs['profiles']['a'])
        self.assertTrue(self.alert(obs))

    def test_documented_duplicate_boundary(self):
        obs=copy.deepcopy(self.pre); obs['duplicateIds']=['a']
        self.assertFalse(self.alert(obs))
        self.assertFalse(self.ns['projection_equal'](obs,self.pre))

    def test_policy_guards_semantics_only_if_reference_is_independent(self):
        obs=copy.deepcopy(self.pre); obs['profiles']['a']['fqdn']='bad.invalid'
        self.assertFalse(semantic_policy_matches(obs,self.pre))
        self.assertTrue(semantic_policy_matches(obs,obs))

    def test_unattacked_type_counts_as_negative_even_during_attack_tick(self):
        m=matrix()
        add(m,True,True); add(m,False,True); add(m,False,False); add(m,True,False)
        self.assertEqual(m,{'TP':1,'FN':1,'FP':1,'TN':1})

    def test_missing_witness_is_rejection(self):
        with self.assertRaises(ValueError):
            self.ns['reference_witness_consistent']({},None,'initial','nonce')


if __name__=='__main__':
    unittest.main()
