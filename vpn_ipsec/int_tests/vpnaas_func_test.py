'''
Unit tests for VPNaaS

'''
import unittest,sys

from vpnaas import vpnaas
from vpnaas.junos.junos_ike import DeadPeerDetection, LocalIdentity


class Test(unittest.TestCase):


    def setUp(self):
        pass


    def tearDown(self):
        pass


    def test_add_ipsec_proposal(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        ipsecProposal = vpnaas.add_ipsec_proposal('test_name_A', 'esp',
                                                  'hmac-md5-96', '3des-cbc',
                                                  '180 seconds')
        
        self.assertEqual('test_name_A', ipsecProposal.name,
                         'Proposal names must be set')
        self.assertEqual('esp', ipsecProposal.protocol, 'Protocol must be set')
        self.assertEqual('hmac-md5-96', ipsecProposal.authentication_algorithm,
                         'Authentication algorithm must be set')
        self.assertEqual('3des-cbc', ipsecProposal.encryption_algorithm,
                         'Encryption algorithm must be set')
        self.assertEqual(180, ipsecProposal.lifetime_seconds,
                         'Lifetime-seconds must be set')
        self.assertEqual(-1, ipsecProposal.lifetime_kilobytes,
                         'Lifetime-kilobytes must not be set')
        

    def test_add_ipsec_policy(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        iPsecPolicy = vpnaas.add_ipsec_policy('VPN_NEW', 'test_name_A')
        
        self.assertEqual('VPN_NEW', iPsecPolicy.name, 'Policy name must be set')
        self.assertEqual(1, len(iPsecPolicy.proposals),
                         'Proposal names must have 1 element')
        self.assertEqual('test_name_A', iPsecPolicy.proposals[0],
                         'Proposal name must be set')


    def test_create_ipsec_tunnel(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        ipsecProposal = vpnaas.add_ipsec_proposal('test_proposal', 'esp',
                                                  'hmac-md5-96', '3des-cbc',
                                                  '180 seconds')
        iPsecPolicy = vpnaas.add_ipsec_policy('test_policy', 'test_proposal')
        iPsecProxyId = vpnaas.add_ipsec_proxy_id('1.1.1.1/24', '2.2.2.2/29',
                                                 'any')
        iPsecIKE = vpnaas.add_ipsec_ike('test-gateway', iPsecProxyId,
                                        iPsecPolicy)
        iPsecVPN = vpnaas.add_ipsec_vpn('test_vpn', 'st0', iPsecIKE,
                                        'immediately')
        
        # TODO create an IKE gateway first. won't work now
        vpnaas.create_ipsec_tunnel(ipsecProposal, iPsecPolicy, iPsecVPN)


    def test_create_ike(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        ikeProposal = vpnaas.add_ike_proposal('test-ike-proposal',
                                              'pre-shared-keys', 'group1',
                                              'sha1', '3des-cbc', 28800)
        ikePolicy = vpnaas.add_ike_policy('test-ike-policy', 'main',
                                          'test-ike-proposal',
                                          '$9$E4GcyebwgaJDev4aZjPfO1REyK8X-')
        
        deadPeerDetection = DeadPeerDetection()
        deadPeerDetection.always_send = True
        deadPeerDetection.interval = 10
        deadPeerDetection.threshold = 2
        
        localIdentity = LocalIdentity()
        localIdentity.inet = '1.1.1.1'
        localIdentity.hostname = 'hostname'
        localIdentity.user_at_hostname = 'user@hostname'
        localIdentity.distinguished_name = True
        
        ikeGateway = vpnaas.add_ike_gateway('test-gateway', 'test-ike-policy',
                                            '2.2.2.2', deadPeerDetection,
                                            localIdentity, 'st0')
        
        vpnaas.create_ike(ikeProposal, ikePolicy, ikeGateway)

    def test_create_sec_policies(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        policy_rule = vpnaas.add_sec_policy_rule('test-policy-rule', 'any', 
            'any', 'any', 'permit')

        vpnaas.create_sec_policies('zone-A', 'zone-B', policy_rule)
        

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.test_add_ipsec_proposal',
    #                        'Test.test_add_ipsec_policy',
    #                        'Test.test_create_ipsec_tunnel']
    unittest.main()
