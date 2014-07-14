'''
Data validator

'''

import re


__ip_regex_matcher = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]'\
                                + '|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}'\
                                + '|2[0-4][0-9]|25[0-5])$')

__ip_cidr_regex_matcher = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]'\
                                     + '[0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]'\
                                     + '|1[0-9]{2}|2[0-4][0-9]|25[0-5])'\
                                     + '(\/(\d|[1-2]\d|3[0-2]))$')

def valid_ip(ip):
    return __ip_regex_matcher.match(ip)

def valid_ip_cidr(ip_cidr):
    return __ip_cidr_regex_matcher.match(ip_cidr)

def isHexadecimal(text):
    try:
        int(text, 16)
        return True
    except ValueError:
        return False

def isAscii(text):
    try:
        text.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False
