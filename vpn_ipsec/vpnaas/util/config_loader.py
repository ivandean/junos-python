'''
Configuration loader class

'''

from ConfigParser import SafeConfigParser
import os

import vpnaas


NETCONF_SECTION = 'NETCONF_JUNOS'
SERVER_HOST = 'server_host'
SERVER_PORT = 'server_port'
SERVER_USER = 'server_user'
SERVER_PASSWORD = 'server_password'

IKE_SECTION = 'IKE_JUNOS'
PRE_SHARED_KEY = 'presharedkey'

class ConfigLoader(object):
    
    configReader = None

    def __init__(self, config_file_path=None):
        self.configReader = SafeConfigParser()
        if config_file_path is None:
            config_file_path = os.path.realpath(vpnaas.__file__ + \
                                                '/../../config.ini')
            
        self.configReader.read(config_file_path)
    
    def get_netconf(self, key):
        return self.configReader.get(NETCONF_SECTION, key)

    def get_ike(self, key):
        return self.configReader.get(IKE_SECTION, key)
