'''
Unit tests for NetconfClient class

'''
import unittest,sys

from lxml import etree

from junos.netconf_client import NetconfClient
from ncclient.xml_ import new_ele, sub_ele
from vpnaas.util import config_loader


class Test(unittest.TestCase):

    host = None
    port = None
    username = None
    password = None

    def setUp(self):
        config_reader = config_loader.ConfigLoader()
        self.host = config_reader.get_netconf(config_loader.SERVER_HOST)
        self.port = config_reader.get_netconf(config_loader.SERVER_PORT)
        self.username = config_reader.get_netconf(config_loader.SERVER_USER)
        self.password = config_reader.get_netconf(config_loader.SERVER_PASSWORD)


    def tearDown(self):
        pass


    def test_get_config(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        nc = NetconfClient(self.host, self.port, self.username, self.password)
        config = nc.get_config()
        self.assertTrue(config != None, 'Configuration must be set.')
        print 'Configuration obtained:\n'\
            + etree.tostring(config, pretty_print=True, encoding=unicode)
        self.assertNotEquals(None, config)

        config_filter = new_ele('configuration')
        system_ele = sub_ele(config_filter, 'system')
        sub_ele(system_ele, 'license')
        config = nc.get_config(config_filter)
        self.assertTrue(config != None, 'Filtered configuration must be set.')
        print 'Filtered configuration obtained:\n'\
            + etree.tostring(config, pretty_print=True, encoding=unicode)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_get_config']
    unittest.main()
