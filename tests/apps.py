#!/usr/bin/env python

import os
import sys
import unittest

dirname = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(dirname, ".."))

from oshift import *

class TestUser(unittest.TestCase):
    """
    Test REST API related to app only test one framework for quick testing
    """
    li = None
    domain_name = "autotest"
    app_name = "myapp"

    def setUp(self):
        self.assertTrue(os.environ.has_key('OPENSHIFT_USER'),
            'Missing Openshift username!')
        self.assertTrue(os.environ.has_key('OPENSHIFT_PASSWD'),
            'Missing Openshift password!')
        self.assertTrue(os.environ.has_key("OPENSHIFT_IP"),
            'Missing instance ip variable!')
        li = Openshift(host=os.getenv('OPENSHIFT_IP'), user=os.getenv('OPENSHIFT_USER'),
            passwd=os.getenv('OPENSHIFT_PASSWD'))
        self.li = li
        status, res = li.domain_create(self.domain_name)

        if status != 201:
            msg = res['messages'][0]['text']
            raise OpenShiftNullDomainException("Unable to create domain: %s" % msg)

    def test_app_create_delete(self):
        status, res = self.li.app_create(app_name=self.app_name, app_type="php-5.3")
        self.assertTrue(status, 'Created')
        status, res = self.li.app_delete(self.app_name)
        self.assertTrue(status, 'No Content')
        print status

    def tearDown(self):
        print "####################"
        status, res = self.li.domain_delete(self.domain_name)

    """
    @classmethod
    def tearDownClass(cls):
        print '######## Cleaning up... #################'
        cls.li.domain_delete(cls.domain_name)
    """
if __name__ == '__main__':
    """
    li = Openshift(host=os.getenv('OPENSHIFT_IP'), user=os.getenv('OPENSHIFT_USER'),
            passwd=os.getenv('OPENSHIFT_PASSWD'))
    status, res = li.app_create(app_name='myapp', app_type='php-5.3')
    print status
    """
    unittest.main()
