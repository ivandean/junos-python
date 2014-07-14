'''
Logging util

'''

import logging

class LoggerUtil(object):

    CRITICAL = 50
    ERROR = 40
    WARNING = 30
    INFO = 20
    DEBUG = 10
    NOTSET = 0

    def __init__(self, level='NOTSET'):
        FORMAT = '[%(levelname)s][%(asctime)-15s]: %(message)s'
        logging.basicConfig(
            format=FORMAT, level=logging.getLevelName(level.upper()))

    def log(self, lvl, message):
        logging.log(lvl, message)

    def debug(self, message):
        logging.debug(message)
        # self.log(self.DEBUG, message)

    def info(self, message):
        logging.info(message)
        # self.log(self.INFO, message)

    def error(self, message):
        logging.error(message)
