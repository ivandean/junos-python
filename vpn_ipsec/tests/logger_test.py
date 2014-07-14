'''
Unit tests for LoggerUtil

'''

import unittest,sys
from vpnaas.util import logger_util


class TestLogger(unittest.TestCase):


    def setUp(self):
        self.LOGGER = logger_util.LoggerUtil('debug')
        pass

    def tearDown(self):
        pass

    def test_log(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        self.LOGGER.log(self.LOGGER.ERROR,
                        "ERROR message test using 'log' method")
        self.LOGGER.log(self.LOGGER.INFO,
                        "INFO message test using 'log' method")
        self.LOGGER.debug("Debug message test")
        self.LOGGER.info("Info message test")
        self.LOGGER.error("Error message test")


if __name__ == "__main__":
    unittest.main()
