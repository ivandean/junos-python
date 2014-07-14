'''
Unit tests for VPNaaS

'''
import unittest,sys

from vpnaas import vpnaas
from vpnaas.junos.junos_ipsec import IPsecProposal
from vpnaas.junos.junos_ike import IKEProposal, IKEPolicy

class TestExceptions(unittest.TestCase):


    def setUp(self):
        pass


    def tearDown(self):
        pass

    def test_add_ipsec_proposal(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        self.assertRaises(ValueError, 
            vpnaas.add_ipsec_proposal,'','','','','')
        self.assertRaises(ValueError, 
            vpnaas.add_ipsec_proposal,'test_name_A','','','','')
        self.assertRaises(ValueError, 
            vpnaas.add_ipsec_proposal,'test_name_A','esp','','','')
        self.assertRaises(ValueError, 
            vpnaas.add_ipsec_proposal,'test_name_A','esp','hmac-md5-96','','')
        self.assertRaises(ValueError, 
            vpnaas.add_ipsec_proposal,'test_name_A','esp','hmac-md5-96',
            '3des-cbc','')
    
    def test_add_ipsec_policy(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        self.assertRaises(ValueError, vpnaas.add_ipsec_policy,'','')
        self.assertRaises(ValueError, vpnaas.add_ipsec_policy,'VPN_NEW','')

    def test_add_ipsec_proxy_id(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        self.assertRaises(ValueError,vpnaas.add_ipsec_proxy_id,'','','')
        self.assertRaises(ValueError,vpnaas.add_ipsec_proxy_id,'1.1.1.1/24',''
            ,'')
        self.assertRaises(ValueError,vpnaas.add_ipsec_proxy_id,'1.1.1.1/24',
            '2.2.2.2/29','')

    def test_add_ipsec_ike(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        iPsecProxyId = vpnaas.add_ipsec_proxy_id('1.1.1.1/24', '2.2.2.2/29',
                                                 'any')

        self.assertRaises(ValueError,vpnaas.add_ipsec_ike,'','','')
        self.assertRaises(ValueError,vpnaas.add_ipsec_ike,'test-gateway','','')
        self.assertRaises(ValueError,vpnaas.add_ipsec_ike,'test-gateway',
            iPsecProxyId,'')

    def test_create_ipsec_tunnel(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        
        iPsecProposal = IPsecProposal('test_proposal')
        iPsecProposal.protocol = 'esp'
        iPsecProposal.authentication_algorithm = 'hmac-md5-96' 
        iPsecProposal.encryption_algorithm = '3des-cbc'
        iPsecProposal.lifetime_seconds = 180
        
        iPsecPolicy = vpnaas.add_ipsec_policy('test_policy', 'test_proposal')
       
        self.assertRaises(ValueError,vpnaas.create_ipsec_tunnel,'','','')
        self.assertRaises(ValueError,vpnaas.create_ipsec_tunnel,iPsecProposal,
            '','')
        self.assertRaises(ValueError,vpnaas.create_ipsec_tunnel,iPsecProposal,
            iPsecPolicy,'')
        self.assertRaises(ValueError,vpnaas.create_ipsec_tunnel,'non-valid',
            iPsecPolicy,'')

    def test_create_ike(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        
        ikeProposal = IKEProposal('test-ike-proposal')
        ikeProposal.authentication_method = 'pre-shared-keys'
        ikeProposal.dh_group = 'group1'
        ikeProposal.authentication_algorithm = 'sha1'
        ikeProposal.encryption_algorithm = '3des-cbc'
        ikeProposal.lifetime_seconds = 28800
    
        ikePolicy = IKEPolicy('test-ike-policy')
        ikePolicy.mode = 'main'
        ikePolicy.proposal_name = 'test-ike-proposal'
        ikePolicy.pre_shared_key = '$9$E4GcyebwgaJDev4aZjPfO1REyK8X-'
        
        self.assertRaises(ValueError,vpnaas.create_ike,'','','')
        self.assertRaises(ValueError,vpnaas.create_ike,ikeProposal,'','')
        self.assertRaises(ValueError,vpnaas.create_ike,ikeProposal,ikePolicy,'')

    def test_add_sec_policy_rule(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        self.assertRaises(ValueError,vpnaas.add_sec_policy_rule,'','','','','')
        self.assertRaises(ValueError,vpnaas.add_sec_policy_rule,
            'test-policy-rule','','','','')
        self.assertRaises(ValueError,vpnaas.add_sec_policy_rule,
            'test-policy-rule','any','','','')
        self.assertRaises(ValueError,vpnaas.add_sec_policy_rule,
            'test-policy-rule','any','any','','')
        self.assertRaises(ValueError,vpnaas.add_sec_policy_rule,
            'test-policy-rule','any','any','junos-cifs','')

    def test_create_sec_policies(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        self.assertRaises(ValueError,vpnaas.create_sec_policies,'','','')
        self.assertRaises(ValueError,vpnaas.create_sec_policies,'zone-A','','')
        self.assertRaises(ValueError,vpnaas.create_sec_policies,'zone-A',
            'zone-B','')

if __name__ == '__main__':
    # import sys;sys.argv = ['', 'Test.test_add_ipsec_proposal',
    #                        'Test.test_add_ipsec_policy',
    #                        'Test.test_create_ipsec_tunnel']
    unittest.main()
