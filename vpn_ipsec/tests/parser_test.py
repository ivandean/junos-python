'''
Unit tests for VPNaaS - XMLParser

'''

import unittest,sys
from vpnaas.util import xml_parser as XMLParser


class TestParser(unittest.TestCase):


    def setUp(self):
        self.XML = '<rpc-reply xmlns:junos="http://xml.juniper.net/junos/'\
                   + '11.4R9/junos"><configuration><security> <ipsec>'\
                   + ' <proposal> <name>VPN-Proposal-A</name> <protocol>'\
                   + 'esp</protocol> <authentication-algorithm>hmac-sha1-96'\
                   + '</authentication-algorithm> <encryption-algorithm>'\
                   + '3des-cbc</encryption-algorithm> <lifetime-seconds>'\
                   + '180..86400 seconds</lifetime-seconds> or '\
                   + '<lifetime-kilobytes>64..4294967294</lifetime-kilobytes>'\
                   + '</proposal><policy><name>IPSec-Policy-A</name>'\
                   + '<proposals>VPN-Proposal-A</proposals></policy><vpn>'\
                   + '<name>VPN-Name-A</name><bind-interface>st0.10'\
                   + '</bind-interface><ike><gateway>VPN-Gateway-A</gateway>'\
                   + '<proxy-identity><local>1.1.1.1/25</local><remote>'\
                   + '2.2.2.2/29</remote><service>any</service>'\
                   + '</proxy-identity><ipsec-policy>IPSec-Policy-A'\
                   + '</ipsec-policy></ike><establish-tunnels>immediately'\
                   + '</establish-tunnels></vpn></ipsec></security>'\
                   + '</configuration></rpc-reply>'
        self.PARSER = XMLParser.XMLParser(self.XML)
        pass

    def tearDown(self):
        pass


    def test_parser_load(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        self.assertEquals("VPN-Proposal-A",
         self.PARSER.get_value("./configuration/security/ipsec/proposal/name"))
        self.PARSER.set_value("./configuration/security/ipsec/proposal/name",
                              "New VPN")
        self.PARSER.set_attrib("./configuration", "attrib", "atributo!")
        self.assertEquals("New VPN",
          self.PARSER.get_value("./configuration/security/ipsec/proposal/name"))
        self.assertEquals("atributo!",
                          self.PARSER.get_attrib("./configuration", "attrib"))

    def test_generate_xml(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        self.PARSER = XMLParser.XMLParser(root_tag="root")
        root = self.PARSER.get_root()
        leaf1 = self.PARSER.generate_new_subelement(root, "a")
        self.assertEquals("/root/a", self.PARSER.get_path(root, leaf1))
        leaf2 = self.PARSER.generate_new_subelement(root, "b")
        leaf2_1 = self.PARSER.generate_new_subelement(leaf2, "b1")
        self.assertEquals("/root/b/b1", self.PARSER.get_path(root, leaf2_1))
        self.assertEquals("/root/a", self.PARSER.get_path(root, leaf1))


if __name__ == "__main__":
    unittest.main()
