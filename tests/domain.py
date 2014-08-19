#!/usr/bin/env python

import os
import sys
import unittest

dirname = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(dirname, ".."))

from oshift import *

class TestUser(unittest.TestCase):
    """
    Test domain get REST API, under /broker/rest/domains
    The available actions are:
        UPDATE, DELETE, LIST_APPLICATIONS, GET, ADD_APPLICATION,
    """
    valid_domain_name = "autotest"

    def test_invalid_domain(self):
        self.assertTrue(os.environ.has_key('OPENSHIFT_USER'),
            'Missing Openshift username!')
        self.assertTrue(os.environ.has_key('OPENSHIFT_PASSWD'),
            'Missing Openshift password!')
        self.assertTrue(os.environ.has_key("OPENSHIFT_IP"),
            'Missing instance ip variable!')

        li = Openshift(host=os.getenv('OPENSHIFT_IP'), user=os.getenv('OPENSHIFT_USER'),
                passwd=os.getenv('OPENSHIFT_PASSWD'))

        status, res = li.domain_create('invalid domain name')
        expected = "Invalid namespace. Namespace must only contain alphanumeric characters."
        error_msg = res['messages'][0]['text']
        self.assertEqual(error_msg, expected)

    def test_domain_create(self):
        self.assertTrue(os.environ.has_key('OPENSHIFT_USER'),
            'Missing Openshift username!')
        self.assertTrue(os.environ.has_key('OPENSHIFT_PASSWD'),
            'Missing Openshift password!')
        self.assertTrue(os.environ.has_key("OPENSHIFT_IP"),
            'Missing instance ip variable!')
        li = Openshift(host=os.getenv('OPENSHIFT_IP'), user=os.getenv('OPENSHIFT_USER'),
            passwd=os.getenv('OPENSHIFT_PASSWD'))
        status, res = li.domain_create(self.valid_domain_name)
        expected_status = 201
        self.assertEqual(status, expected_status)

    def test_domain_delete(self):

        self.assertTrue(os.environ.has_key('OPENSHIFT_USER'),
            'Missing Openshift username!')
        self.assertTrue(os.environ.has_key('OPENSHIFT_PASSWD'),
            'Missing Openshift password!')
        self.assertTrue(os.environ.has_key("OPENSHIFT_IP"),
            'Missing instance ip variable!')
        li = Openshift(host=os.getenv('OPENSHIFT_IP'), user=os.getenv('OPENSHIFT_USER'),
            passwd=os.getenv('OPENSHIFT_PASSWD'))
        status, res = li.domain_delete(self.valid_domain_name, force=True)
        expected_status = 204
        self.assertEqual(status, expected_status)

if __name__ == '__main__':
    """
    li = Openshift(host=os.getenv('OPENSHIFT_IP'), user=os.getenv('OPENSHIFT_USER'),
            passwd=os.getenv('OPENSHIFT_PASSWD'))

    status, res = li.domain_create('invalid domain name')
    expected = "Invalid namespace: 'invalid domain name'. Namespace must only contain alphanumeric characters."
    error_msg = res.json['messages'][0]['text']
    self.assertEqual(error_msg, expected)
    """
    unittest.main()
