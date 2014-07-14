'''
Unit tests for ConfigReader

'''

import os,sys,unittest

import vpnaas
from vpnaas.util import config_loader
from ConfigParser import NoOptionError


class TestConfig(unittest.TestCase):


    def setUp(self):
        self.config = config_loader.ConfigLoader(config_file_path=
                                        os.path.realpath(vpnaas.__file__ + 
                                        '/../../config.ini.sample'))
        pass

    def tearDown(self):
        pass

    def test_config(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        self.assertEquals('hostname',
                          self.config.get_netconf(config_loader.SERVER_HOST))
        self.assertEquals('12345',
                          self.config.get_netconf(config_loader.SERVER_PORT))
        self.assertEquals('user',
                          self.config.get_netconf(config_loader.SERVER_USER))
        self.assertEquals('password',
                        self.config.get_netconf(config_loader.SERVER_PASSWORD))
        self.assertEquals('abcdefghijklmnopqrstuvwxyz',
                          self.config.get_ike(config_loader.PRE_SHARED_KEY))
        
        self.assertRaises(NoOptionError, self.config.get_netconf, 'no_key')
        self.assertRaises(NoOptionError, self.config.get_ike, 'no_key')


if __name__ == "__main__":
    unittest.main()
