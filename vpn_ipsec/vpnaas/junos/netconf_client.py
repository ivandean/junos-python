'''
Netconf ncclient wrapper

'''
from lxml import etree
from ncclient import manager

from vpnaas.util import logger_util


class NetconfClient(object):
    
    LOGGER = None
    
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        
        self.LOGGER = logger_util.LoggerUtil('debug')
        
    def edit_config(self, new_config, default_operation="merge"):
        try:
            m = manager.connect(host=self.host, port=self.port,
                                username=self.username, password=self.password,
                                unknown_host_cb=lambda x, y: True)
            m.lock()
            add_config = etree.Element("config",
                nsmap={"xc": "urn:ietf:params:xml:ns:netconf:base:1.0"})
            config = etree.SubElement(add_config, "configuration")
            
            if isinstance(new_config, list):
                for nc in new_config:
                    config.append(nc)
            else:
                config.append(new_config)
                
            m.edit_config(
                target='candidate', config=etree.tostring(add_config),
                test_option='test-then-set',
                default_operation=default_operation,
                error_option='stop-on-error')
            m.commit()
        except Exception as e:
            self.LOGGER.error('Error editing configuration: ' + e.message)
            self.LOGGER.error('Discarding changes')
            m.discard_changes()
            raise e
        finally:
            m.unlock()
            m.close_session()

    def get_config(self, config_filter=None):
        try:
            m = manager.connect(host=self.host, port=self.port,
                                username=self.username, password=self.password,
                                unknown_host_cb=lambda x, y: True)
            
            with m.locked('running'):
                if config_filter is not None:
                    config = m.get_configuration(format='xml',
                                                 filter=config_filter)
                else:
                    config = m.get_configuration(format='xml')
        except Exception as e:
            m.discard_changes()
            raise e
        finally:
            m.close_session()
                
        return etree.ElementTree(config.xpath('configuration')[0])
