#!/usr/bin/env python

import os
import sys
import unittest

dirname = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(dirname, ".."))

from oshift import *

class TestUser(unittest.TestCase):
    """
    Test user get REST API  /broker/rest/user
    """
    def test_invalid_username(self):
        li = Openshift(host=os.getenv('OPENSHIFT_IP'), user='pppppp',
                       passwd=os.getenv('OPENSHIFT_PASSWD'))

        status, res = li.get_user()
        expected_status = 401
        self.assertEqual(status, expected_status)

    def test_invalid_password(self):
        li = Openshift(host=os.getenv('OPENSHIFT_IP'), user=os.getenv('OPENSHIFT_USER'),
                       passwd="notvalid")

        status, res = li.get_user()
        expected_status = 401
        self.assertEqual(status, expected_status)


    def test_user(self):
        self.assertTrue(os.environ.has_key('OPENSHIFT_USER'),
            'Missing Openshift username!')
        self.assertTrue(os.environ.has_key('OPENSHIFT_PASSWD'),
            'Missing Openshift password!')
        self.assertTrue(os.environ.has_key("OPENSHIFT_IP"),
            'Missing instance ip variable!')
        li = Openshift(host=os.getenv('OPENSHIFT_IP'), user=os.getenv('OPENSHIFT_USER'),
            passwd=os.getenv('OPENSHIFT_PASSWD'))
        status, res = li.get_user()
        expected_status = 200
        self.assertEqual(status, expected_status)

    def test_add_key(self):
        key_str = "aaabbbcccdddeeefffggghhhiiijjjkkklllmmmnnnooopppqqqrrrssstttuuuvvvwwwxxxyyyzzz"

if __name__ == '__main__':
    #li = Openshift(host=os.getenv('OPENSHIFT_IP'), user=os.getenv('OPENSHIFT_USER'), passwd=os.getenv('OPENSHIFT_PASSWD'))
    #status, res = li.get_user()
    #self.assertEqual(status, 'OK')

    unittest.main()
