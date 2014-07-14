'''
Unit tests for data validation

'''
import unittest,sys

from vpnaas.util import data_validator


class Test(unittest.TestCase):


    def setUp(self):
        pass


    def tearDown(self):
        pass

    def test_valid_ip(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'        
        for ip in ['1.1.1.1', '192.168.1.140', '254.254.254.254']:
            valid = data_validator.valid_ip(ip)
            self.assertTrue(valid, ip + ' must be a valid IP address')
            
        for ip in ['1.1.1', '192.168.1.256', '1.1.1.1/24']:
            valid = data_validator.valid_ip(ip)
            self.assertTrue(not valid, ip + ' must not be a valid IP address')

    def test_valid_ip_cidr(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        for ip_cidr in ['1.1.1.1/0', '1.1.1.1/24', '192.168.1.101/16']:
            valid = data_validator.valid_ip_cidr(ip_cidr)
            self.assertTrue(valid, ip_cidr + ' must be a valid IP/CIDR')
        
        for ip_cidr in ['1.1.1.1/64', '1.1.1.1/-1', '1.1.1.1', '1.1.1.256/24']:
            valid = data_validator.valid_ip_cidr(ip_cidr)
            self.assertTrue(not valid, ip_cidr + ' must not be a valid IP/CIDR')

    def test_hex_ascii(self):
        print ' '
        print '********* ' + sys._getframe().f_code.co_name + ' *********'
        ascii = "$9$E4GcyebwgaJDev4aZjPfO1REyK-"
        hexa = "243924453447637965627767614a44657634615a6a50664f315245794b38582"

        self.assertTrue(data_validator.isAscii(ascii))
        self.assertTrue(data_validator.isHexadecimal(hexa))
        self.assertFalse(data_validator.isHexadecimal(ascii))
        # any hexadecimal string is an ASCII string too
        self.assertTrue(data_validator.isAscii(hexa))

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.test_valid_ip_cidr',
    #                        'Test.test_valid_ip',
    #                        'Test.test_hex_ascii']
    unittest.main()
