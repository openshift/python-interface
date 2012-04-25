#!/usr/bin/env python

"""
This files contains utility classes that are Openshift related.

"""

import httplib, urllib
import base64
import os
import inspect
import json
import exceptions

import logging, logging.handlers
import sys
from optparse import OptionParser

class OpenShiftException(exceptions.BaseException):
    pass

class OpenShiftLoginException(OpenShiftException):
    pass


def config_logger():
    # create formatter
    formatter = logging.Formatter("%(levelname)s [%(asctime)s] %(message)s",
            "%H:%M:%S")
    logger = logging.getLogger("dump_logs")
    log_formatter = logging.Formatter(
        "%(name)s: %(asctime)s - %(levelname)s: %(message)s")

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(stream_handler)
    return logger


def config_parser():
    # these are required options.
    parser.set_defaults(VERBOSE=False)
    parser.set_defaults(DEBUG=False)
    parser.add_option("-d", action="store_true", dest="DEBUG", help="enable DEBUG (default true)")
    #parser.add_option("-a", "--action", help="action you want to take (list|create|store)")
    parser.add_option("-i", "--ip", default="openshift.redhat.com", help="ip addaress of your devenv")
    parser.add_option("-v", action="store_true", dest="VERBOSE", help="enable VERBOSE printing")
    parser.add_option("-u", "--user", default=None, help="User name")
    parser.add_option("-p", "--password", default=None, help="RHT password")
    (options, args) = parser.parse_args()
    
    if options.user is None:
        options.user = os.getenv('OPENSHIFT_user_email')
 
    if options.password is None:
        options.password = os.getenv('OPENSHIFT_user_passwd')

    return options, args


log = config_logger()
parser = OptionParser()

class Response(object):
    """
    A base Response class to derive from.  Handle the JSON response from the
    REST API

    """
    json = None
    body = None
    status = httplib.OK
    headers = {}
    error = None
    url = None
    debug = False

    def __init__(self, response, base_url, debug=False):
        self.body = response.read()
        self.status = response.status
        self.headers = dict(response.getheaders())
        self.error = response.reason
        self.url = base_url
        self.parse_body()
        self.data = None

    def parse_body(self):
        """
        call JSON library to translate string JSON response to a JSON object
        """
        if len(self.body) > 2:  # just in cases where API return just '{}'
            try:
                self.json = json.loads(self.body)
            except:
                return self.body

        # the acutal JSON response is key by the url (w/o the leading slash
            self.data =self.json['data']
        else:
            self.data = None

        if self.debug:
            self.pprint()

        return self.data

    def pprint(self):  # pretty print
        """ do pretty print of JSON response """
        print json.dumps(self.json, sort_keys=True, indent=2)

    def __unicode__(self):
        return self.pprint(self.json)

class RestApi(object):
    """
    A base connection class to derive from.
    """

    conn_classes = (httplib.HTTPConnection, httplib.HTTPSConnection)
    connection = None
    host = '127.0.0.1'
    port = (80, 443)
    secure = 1 # 0 or 1
    username = None
    password = None
    responseCls = Response
    headers = None
    response = None
    base_uri = '/broker/rest'
    verbose = False
    debug = False

    def __init__(self, host=None, port=80, username=username, password=password,
            debug=False, verbose=False, secure=True):
        if host is not None:
            self.host = host

        if username:
            self.username = username

        if password:
            self.password = password

        if verbose:
            self.verbose = verbose

        self.connection = self.conn_classes[self.secure](self.host,
                self.port[self.secure])

        if debug:
            self.debug = debug
            self.responseCls.debug = self.debug
            print self.responseCls.debug
            #self.responseCls = Response(response=self.response, base_url=self.base_uri, debug=debug)

    def connect(self, host=None, port=80, headers=None):
        if host:
            self.host = host

        if port:
            self.port = port
        else:
            self.port = self.port[self.secure]
        kwargs = {'host': host, 'port': port}
        connection = self.conn_classes[self.secure](**kwargs)
        self.connection = connection
        return connection

    def _get_auth_headers(self, username=None, password=None):
        if username:
            self.username = username
        if password:
            self.password = password

        return {
                "Content-type": "application/x-www-form-urlencoded",
                'Authorization':
                    "Basic %s"
                    % base64.b64encode('%s:%s' % (self.username, self.password)),
                'Accept': 'application/json'
                }
    def request(self, url, method, headers=None, params=None):
        conn = self.connection
        if url is None:
            raise OpenShiftException("No valid url found!")

        if url.startswith("https://"):
            self.url = url # self.base_uri + url
        else:
            self.url = self.base_uri + url

        log.debug("URL: %s" % self.url)
        if self.headers is None:
            self.headers = self._get_auth_headers(self.username, self.password)
        conn.set_debuglevel(0)
        if method == 'GET':
            conn.request(method=method,url=self.url,headers=self.headers)
        else:
            conn.request(method=method,url=self.url,body=params, headers=self.headers)

        raw_response = conn.getresponse()

        self.response = self.responseCls(raw_response, self.url)
        self.data = self.response.parse_body()
        
        return (self.response.error, raw_response)
    

    def GET(self, url):
        """ wrapper around request() """
        url = self.base_uri
        res = self.request(url, method="GET")
        return res

    def POST(self, data):
        """ do a REST API POST """
        return self.connection.request(url=self.url, headers=self.headers, body=data, method='POST')

    def PUT(self, url, data):
        return self.connection.request(url=self.url, params=data, method='PUT')

class Openshift(object):
    """
    wrappers class around REST API so use can use it with python
    """
    rest = None
    user = None 
    passwd = None 


    def __init__(self, host, user=None, passwd=None, debug=False, verbose=False):
        if user:
            self.user = user
        if passwd:
            self.passwd = passwd

        self.rest = RestApi(host=host, username=self.user, password=self.passwd, debug=debug, verbose=verbose)

    def get_href(self, top_level_url, target_link, domain_name=None):
        status, res = self.rest.request(method='GET', url=top_level_url)
        index = target_link.upper()
        if domain_name is None:
            res = self.rest.response.json['data'][0]['links'][index]
            return (res['href'], res['method'])

        else:  # domain name is specified, now find a match
            json_data = self.rest.response.json['data']
            if json_data:
                for jd in json_data:
                    if jd['id'] == domain_name:
                        res = jd['links'][index]
                        return (res['href'], res['method'])
            else:
                return(None, None)
        
    ##### /user  (sshkey)
    def get_user(self):
        (status, raw_response) = self.rest.request(method='GET', url='/user')
        if status == 'OK':
            return (status, self.rest.response.json['data']['login'])
        else:
            return (status, raw_response)

    def list_keys(self):
        log.debug("Getting ssh key information...")
        (status, raw_response) = self.rest.request(method='GET', url='/user/keys')
        return (status, raw_response)

    def add_key(self, kwargs):
        """
        params: {name, type, key_path}
        """
        if not kwargs.has_key('key'):
            # use a default path
            sshkey = '~/.ssh/id_rsa.pub'
        else:
            sshkey = kwargs['key']
        ssh_path = os.path.expanduser(sshkey)
        ssh_key_str = open(ssh_path, 'r').read().split(' ')[1]

        if not kwargs.has_key('name'):

            kwargs['name'] = 'default'

        if not kwargs.has_key('type'):
            kwargs['type'] = 'ssh-rsa'

        data_dict = {
                    'name': kwargs['name'],
                    'type': kwargs['type'],
                    'content': ssh_key_str
                    }

        params = urllib.urlencode(data_dict)
        status, raw_response = self.rest.request(method='POST', url='/user/keys', params=params)
        return (status, raw_response)


    ##### /domains
    def domain_create(self, name, rhlogin='pruan@redhat.com'):
        log.debug("Creating domain '%s'" % name)
        TESTDATA = {
        'id': name,
        'rhlogin': rhlogin
        }

        params = urllib.urlencode(TESTDATA)

        self.rest.request(method='POST', url='/domains', params=params)
        if self.rest.response.status == 201:
            log.info("Domain name '%s' created successfully." % name)
        else:
            log.info("Domain creation failed, reason: %s" % self.rest.response.body)
        return (self.rest.response.status,self.rest.response)


    def domain_delete(self, domain_name, force=True):
        """ destory a user's domain, if no name is given, figure it out"""
        url, method = self.get_href('/domains', 'delete', domain_name)

        if force:
            params = urllib.urlencode({'force': 'true'})
        (status, raw_response)= self.rest.request(method=method,  url=url, params=params)
        return (status, raw_response)


    def domain_get(self, name):
        log.debug("Getting domain information...")
        url, method = self.get_href('/domains', 'get', name)
        if url:
            (status, raw_response) = self.rest.request(method=method, url=url)

            if status == 'OK':
                return (status, self.rest.response.json['data']['id'])
        else:
            return ('Not Found', self.rest.response.json['data'])

    def domain_update(self, new_name):
        params = urllib.urlencode({'namespace': new_name})
        url, method = self.get_href("/domains", 'update')
        (status, res) = self.rest.request(method=method, url=url, params=params)
        return (status, res)

    def app_list(self):
        url, method = self.get_href('/domains', 'list_applications')
        (status, res) = self.rest.request(method=method, url=url)
        return (status, self.rest.response.json)

    def app_create(self, app_name, app_type, scale='false'):
        url, method = self.get_href('/domains', 'add_application')
        valid_options = self.rest.response.json['data'][0]['links']['ADD_APPLICATION']['optional_params'][0]['valid_options']

        if app_type not in valid_options:
            log.error("The app type you specified '%s' is not supported!" % app_type)
            log.debug("supported apps types are: %s" % valid_options)
        data_dict = {
                     'name' : app_name,
                     'cartridge' : app_type,
                     'scale' : scale
                     }
        params = urllib.urlencode(data_dict)
        log.debug("URL: %s, METHOD: %s" % (url, method))
        (status, res) = self.rest.request(method=method, url=url, params=params)
        return (status, res)

    ##### /cartridges
    def cartridges(self):
        (status, raw_response) = self.rest.request(method='GET', url='/cartridges')
        if status == 'OK':
            # return a list of cartridges that are supported
            return (status, self.rest.response.json['data'])
        else:
            return (status, raw_response)

    ##### /api  get a list of support operations
    def api(self):
        log.debug("Getting supported APIs...")
        (status, raw_response) = self.rest.request(method='GET', url='/api')
        return (status, raw_response)



    ##### helper functions
    def do_action(self, kwargs):
        op = kwargs['op_type']
        if op == 'cartridge':
            status, res = self.list_cartridges(kwargs['app_name'])
        elif op == 'keys':
            status, res = self.list_keys()

        json_data = self.rest.response.json
        action = kwargs['action']
        name = kwargs['name']
        for data in json_data['data']:
            if data['name'] == name:
                params = data['links'][action]
                log.debug("Action: %s" % action)
                if len(params['required_params']) > 0:
                    # construct require parameter dictionary
                    data = {}
                    for rp in params['required_params']:
                        param_name = rp['name']
                        if kwargs['op_type'] == 'cartridge':
                            data[param_name] = action.lower()
                        else:
                            data[param_name] = kwargs[param_name]
                    data = urllib.urlencode(data)
                else:
                    data = None
                (status, raw_response) =  self.rest.request(method=params['method'],
                                                    url=params['href'],
                                                    params=data)
                return (status, raw_response)

        return (status, raw_response)

    #### application tempalte
    def app_templates(self):
        (status, raw_response) = self.rest.request(method='GET', url='/application_template')
        if status == 'OK':
            return (status, self.rest.response.json)
        else:
            return (status, raw_response)

    ##### keys
    def delete_key(self, key_name):
        params = {"action": 'DELETE', 'name': key_name, "op_type": 'keys'}
        return self.do_action(params)


    def key_update(self, kwargs): #key_name, key_path, key_type='ssh-rsa'):
        key_path = kwargs['key']
        key_name = kwargs['name']
        if kwargs.has_key('key_type'):
            key_type = kwargs['key_type']
        else:
            key_type = 'ssh-rsa'
        ssh_path = os.path.expanduser(key_path)
        ssh_key_str = open(ssh_path, 'r').read().split(' ')[1]

        params = {'op_type':'keys', 'action': 'UPDATE', 'name': key_name, 'content': ssh_key_str, 'type': key_type}
        return self.do_action(params)
    
    def key_get(self, name):
        """  returns the actual key content """
        params = {'action': 'GET', 'name': name, 'op_type': 'keys'}
        status, res = self.do_action(params)
        #status, res = self.key_action(params)
        if status == 'OK':
            return self.rest.response.json['data']['content']
        else:
            return None

    def key_action(self, kwargs):
        status, res = self.list_keys()
        json_data = self.rest.response.json
        action = kwargs['action']
        name = kwargs['name']
        for data in json_data['data']:
            if data['name'] == name:
                params = data['links'][action]
                log.debug("Action: %s" % action)
                if len(params['required_params']) > 0:
                    # construct require parameter dictionary
                    data = {}
                    for rp in params['required_params']:
                        param_name = rp['name']
                        data[param_name] = kwargs[param_name]
                    data = urllib.urlencode(data)
                else:
                    data = None
                break
        (status, raw_response) =  self.rest.request(method=params['method'],
                                                    url=params['href'],
                                                    params=data)
        return (status, raw_response)





    ##### apps
    def app_create_scale(self, app_name, app_type, scale):
        self.app_create(app_name=app_name, app_type=app_type, scale=scale)
        
    def app_delete(self, app_name):
        params = {'action': 'DELETE', 'app_name': app_name}
        return self.app_action(params)

    def app_start(self, app_name):    
        params = {"action": 'START', 'app_name': app_name}
        return self.app_action(params)

    def app_stop(self, app_name):
        params = {"action": 'STOP', 'app_name': app_name}
        return self.app_action(params)

    def app_restart(self, app_name):
        params = {"action": 'RESTART', 'app_name': app_name}
        return self.app_action(params)

    def app_force_stop(self, app_name):
        params = {"action": 'FORCE_STOP', 'app_name': app_name}
        return self.app_action(params)

    def app_get_descriptor(self, app_name):
        params = {'action': 'GET', 'app_name': app_name}
        return self.app_action(params)

    def list_cartridges(self, app_name):
        params = {"action": 'LIST_CARTRIDGES', 'app_name': app_name}
        return self.app_action(params)

    def add_cartridge(self, app_name, cart_name):
        params = {"action": 'ADD_CARTRIDGE', 'app_name': app_name,
                'cart_name': cart_name, 'cartridge': cart_name}
        return self.app_action(params)

    def add_alias(self, app_name, alias):
        params = {"action": 'ADD_ALIAS', 'app_name': app_name, 'alias': alias}
        return self.app_action(params)

    def remove_alias(self, app_name, alias):
        params = {'action': 'REMOVE_ALIAS', 'app_name': app_name, 'alias': alias}
        return self.app_action(params)


    def app_action(self, params):
        """ generic helper function that is capable of doing all the operations
        for application
        """
        # step1. find th url and method
        status, res = self.app_list()
        app_found = False
        action = params['action']
        app_name = params['app_name']

        if params.has_key('cart_name'):
            cart_name = params['cart_name']
        for app in res['data']:
            if app['name'] == app_name:
                # found match, now do your stuff
                params_dict = app['links'][action]
                method = params_dict['method']
                log.info("Action: %s" % action)
                data = {}
                if len(params_dict['required_params']) > 0:
                    param_name = params_dict['required_params'][0]['name']
                    rp = params_dict['required_params'][0]
                    #data[param_name] = cart_name #'name'] = rp['name']
                    for rp in params_dict['required_params']:
                        # construct the data 
                        param_name = rp['name']
                        if param_name == 'event':
                            data[param_name] = rp['valid_options']
                        else:
                            data[param_name] = cart_name #params['op_type']
                            #data[param_name] = params[param_name]
                        print "DATA: %s" % data
                    data = urllib.urlencode(data)
                else:
                    data = None
                req_url = params_dict['href']
                print "DATA: %s, URL: %s, METHOD: %s " % (data, req_url, method)
                (status, raw_response) =  self.rest.request(method=method, url=req_url, params=data)
                app_found = True
                return (status, raw_response)
        if not app_found:
            log.error("Can not find app matching your request '%s'"% app_name)
            return ("Error", None)

    def get_gears(self, app_name, domain_name=None):
        """ return gears information """
        params = {"action": 'GET_GEARS', 'app_name': app_name}
        status, res =  self.app_action(params)
        gear_info = self.rest.response.json['data']
        gear_counts = len(self.rest.response.json['data'][0]['components'])
        return (self.rest.response.json['data'], gear_counts) 

    ################################
    # cartridges
    ################################
    def cartridge_list(self, app_name):
        params = {"action": 'LIST_CARTRIDGES', 'app_name': app_name}
        return self.app_action(params)

    def cartridge_add(self, app_name, cart_name):
        params = {"action": 'ADD_CARTRIDGE', 'app_name': app_name,
                'cart_name': cart_name}
        #params = {"action": 'ADD_CARTRIDGE', 'name': app_name, "op_type": 'cartridge', 'cart_name': cart_name}
        return self.app_action(params)
    
        #return self.app_action(params)
    def cartridge_delete(self, app_name, name):
        params = {"action": 'DELETE', 'name': name, "op_type": 'cartridge', 'app_name': app_name}
        return self.do_action(params)
    
    def cartridge_start(self, app_name, name):
        params = {"action": 'START', 'name': name, "op_type": 'cartridge', 'app_name': app_name}
        return self.do_action(params)
    
    def cartridge_stop(self, app_name, name):
        params = {"action": 'STOP', 'name': name, "op_type": 'cartridge', 'app_name': app_name}
        return self.do_action(params)
     
    def cartridge_restart(self, app_name, name):
        params = {"action": 'RESTART', 'name': name, "op_type": 'cartridge', 'app_name': app_name}
        return self.do_action(params)
    
    def cartridge_reload(self, app_name, name):
        params = {"action": 'RELOAD', 'name': name, "op_type": 'cartridge', 'app_name': app_name}
        return self.do_action(params)
 
    def cartridge_get(self, app_name, name):
        params = {"action": 'GET', 'name': name, "op_type": 'cartridge', 'app_name': app_name}
        return self.do_action(params)


def create_sandbox(*kwargs):
    """
    create a sandbox account

    """
    pass

if __name__ == '__main__':
    (options, args)= config_parser()
    li = Openshift(host=options.ip, user=options.user, passwd=options.password,
            debug=options.DEBUG,verbose=options.VERBOSE)
    #status, res = li.domain_create('pppx')
    status, res =li.domain_delete('pppx')
    #status, res =li.get_user()
    #status, res = li.app_delete(app_name='myphp')
    #status, res = li.app_create(app_name='myphp', app_type='php-5.3')
    #status, res = li.cartridge_add(app_name='myphp', cart_name='mysql-5.1')
    #status, res = li.cartridge_add(app_name='myphp', cart_name='mysql-5.1')
    #status, res = li.cartridge_delete(app_name='myphp', name='mysql-5.1')
    #tatus, res = li.domain_delete('ppp')
    log.info("STATUS: %s, RES: %s" % (status, res))

