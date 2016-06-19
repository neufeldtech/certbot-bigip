"""Module contains classes used by the F5 BIG-IP Configurator."""

import requests

# this is just really annoying
requests.packages.urllib3.disable_warnings()

import json
import os
import logging
import random
import string

from acme import challenges

from certbot import errors
from certbot import interfaces
from certbot import reverter
from certbot import util

from certbot.plugins import common

from collections import defaultdict

from icontrol.session import iControlRESTSession

class Bigip(object):
    """ Object representing a single F5 BIG-IP system

    Function list:
        def __init__(self, host, port, username, password, partition='Common', verify_certificate=False):
        def __str__(self):
        def test(self):
        def get_version(self):
        def active(self):
        def save(self):
        def save_ucs(self, ucs_name):
        def upload_file(self, local_file_name, destination_file_name):
        def exists_crypto_cert(self, object_name):
        def exists_crypto_key(self, object_name):
        def create_crypto_cert(self, object_name, file_name):
        def create_crypto_key(self, object_name, file_name):

        def create_client_ssl_profile(self, object_name, crypto_cert, crypto_key, crypto_chain)

        def exists_irule(self, irule_name):
        def create_irule_HTTP01(self, achall):
        def delete_irule(self, achall):

        def exists_virtual(self, virtual_name):
        def profile_on_virtual(self, virtual_name, profile_type):
        def http_virtual(self, virtual_name):
        def client_ssl_virtual(self, virtual_name):
        def associate_client_ssl_virtual(self, virtual_name, sni):
        def remove_client_ssl_virtual(self, virtual_name, sni):

        def irules_on_virtual(self, virtual_name):
        def associate_irule_virtual(self, achall, virtual_name):
        def remove_irule_virtual(self, achall, virtual_name):

    """

    def __init__(self, host, port, username, password, partition='Common', verify_certificate=False):
        self.host = host
        self.port = port
        self.username = username
        self.__password = password
        self.partition = partition
        self.session = requests.session()
        self.session.auth = (self.username, self.__password)
        self.session.verify = verify_certificate
        self.session.headers.update({'Content-Type':'application/json'})
        self.valid = False
        self.version = "UNKNOWN"

    def __str__(self):
        return "%s@%s:%d" % (self.username, self.host, self.port)

    def test(self):
        try:
            request = self.session.get("https://%s:%d/mgmt/tm/sys/clock" % (self.host, self.port), timeout=4)

            if request.status_code == requests.codes.ok and request.json()['kind'] == 'tm:sys:clock:clockstats':
                return True
            else:
                return False

        except Exception, e:
            msg = ("Connection to F5 BIG-IP iControl REST API on {0} failed."
                   "Error raised was {2}{1}{2}"
                   "(You most probably need to ensure the username and"
                   "password is correct. Make sure you use the --bigip-username"
                   "and --bigip-password options)".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def get_version(self):
        try:
            self.version = self.session.get("https://%s:%d/mgmt/tm/cli/version" % (self.host, self.port), timeout=4).json()['entries']['https://localhost/mgmt/tm/cli/version/0']['nestedStats']['entries']['active']['description']

        except Exception, e:
            msg = ("Connection to F5 BIG-IP iControl REST API on {0} failed."
                   "Error raised was {2}{1}{2}"
                   "(You most probably need to ensure the username and"
                   "password is correct. Make sure you use the --bigip-username"
                   "and --bigip-password options)".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

        return self.version

    def active(self):
        """ Return true if active for any of the traffic groups which virtual servers (self.bigip_vs_list) are within"""

        return True

    def save(self):
        try:
            payload = {}
            payload['command'] = 'save'

            request = self.session.post("https://%s:%d/mgmt/tm/sys/config" % (self.host, self.port), data=json.dumps(payload), timeout=4)

            if request.status_code == requests.codes.ok and request.json()['kind'] == 'tm:sys:clock:clockstats':
                return True
            else:
                return False

        except Exception, e:
            msg = ("Connection to F5 BIG-IP iControl REST API on {0} failed."
                   "Error raised was {2}{1}{2}"
                   "(You most probably need to ensure the username and"
                   "password is correct. Make sure you use the --bigip-username"
                   "and --bigip-password options)".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def save_ucs(self, ucs_name):

        return False

    def upload_file(self, local_file_name, destination_file_name):
        try:
            chunk_size = 512 * 1024

            file_handle = open(local_file_name, 'rb')
            file_size = os.path.getsize(local_file_name)
            start = 0

            while True:
                file_slice = file_handle.read(chunk_size)

                if not file_slice:
                    break

                current_bytes = len(file_slice)
                if current_bytes < chunk_size:
                    end = file_size
                else:
                    end = start + current_bytes

                content_range = "%s-%s/%s" % (start, end - 1, file_size)
                headers =  {
                    'Content-Type': 'application/octet-stream',
                    'Content-Range': content_range,
                }

                request = self.session.post("https://%s:%d/mgmt/shared/file-transfer/uploads/%s" % (self.host, self.port, destination_file_name), data=file_slice, headers=headers, timeout=4)

                start += current_bytes

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("Connection to F5 BIG-IP iControl REST API on {0} failed."
                   "Error raised was {2}{1}{2}"
                   "(You most probably need to ensure the username and"
                   "password is correct. Make sure you use the --bigip-username"
                   "and --bigip-password options)".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def exists_crypto_cert(self, object_name):
        try:
            request = self.session.post("https://%s:%d/mgmt/tm/sys/crypto/cert/~%s~%s" % (self.host, self.port, self.partition, object_name), timeout=4)

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("Connection to F5 BIG-IP iControl REST API on {0} failed."
                   "Error raised was {2}{1}{2}"
                   "(You most probably need to ensure the username and"
                   "password is correct. Make sure you use the --bigip-username"
                   "and --bigip-password options)".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def exists_crypto_key(self, object_name):
        try:
            request = self.session.post("https://%s:%d/mgmt/tm/sys/crypto/key/~%s~%s" % (self.host, self.port, self.partition, object_name), timeout=4)

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("Connection to F5 BIG-IP iControl REST API on {0} failed."
                   "Error raised was {2}{1}{2}"
                   "(You most probably need to ensure the username and"
                   "password is correct. Make sure you use the --bigip-username"
                   "and --bigip-password options)".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def create_crypto_cert(self, object_name, file_name):
        try:
            payload = {}
            payload['command'] = 'install'
            payload['name'] = "/%s/%s" % (self.partition, object_name)
            payload['from-local-file'] = "/var/config/rest/downloads/%s" % file_name

            # Doesn't seem to matter much here if it already exists, objects will be overwritten
            request = self.session.post("https://%s:%d/mgmt/tm/sys/crypto/cert" % (self.host, self.port), data=json.dumps(payload), timeout=4)

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("Connection to F5 BIG-IP iControl REST API on {0} failed."
                   "Error raised was {2}{1}{2}"
                   "(You most probably need to ensure the username and"
                   "password is correct. Make sure you use the --bigip-username"
                   "and --bigip-password options)".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def create_crypto_key(self, object_name, file_name):
        try:
            payload = {}
            payload['command'] = 'install'
            payload['name'] = "/%s/%s" % (self.partition, object_name)
            payload['from-local-file'] = "/var/config/rest/downloads/%s" % file_name
            payload['securityType'] = 'normal'
            # payload['keyType'] = 'rsa-private'

            # Doesn't seem to matter much here if it already exists, objects will be overwritten
            request = self.session.post("https://%s:%d/mgmt/tm/sys/crypto/key" % (self.host, self.port), data=json.dumps(payload), timeout=4)

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("Connection to F5 BIG-IP iControl REST API on {0} failed."
                   "Error raised was {2}{1}{2}"
                   "(You most probably need to ensure the username and"
                   "password is correct. Make sure you use the --bigip-username"
                   "and --bigip-password options)".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def create_client_ssl_profile(self, object_name, crypto_cert=None, crypto_key=None, crypto_chain=None, server_name=None):
        try:
            if crypto_cert == None:
                crypto_cert = 'default.crt'

            if crypto_key == None:
                crypto_key = 'default.key'

            payload = {}
            payload['name'] = object_name
            payload['partition'] = self.partition
            payload['defaultsFrom'] = '/Common/clientssl'
            payload['cert'] = crypto_cert
            payload['key'] = crypto_key

            if crypto_chain != None:
                payload['chain'] = crypto_chain

            if server_name != None:
                payload['serverName'] = server_name

            request = self.session.post("https://%s:%d/mgmt/tm/ltm/profile/client-ssl" % (self.host, self.port), data=json.dumps(payload), timeout=4)

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("Connection to F5 BIG-IP iControl REST API on {0} failed."
                   "Error raised was {2}{1}{2}"
                   "(You most probably need to ensure the username and"
                   "password is correct. Make sure you use the --bigip-username"
                   "and --bigip-password options)".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def exists_irule(self, irule_name):
        try:
            request = self.session.get("https://%s:%d/mgmt/tm/ltm/rule/~%s~%s" % (self.host, self.port, self.partition,irule_name), timeout=4)

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("iRule creation on {0} failed. {2}{1}{2}".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def create_irule_HTTP01(self, achall):
        try:
            # Create all of the challenge responses within the iRule
            token = achall.chall.encode("token")
            irule_name = "Certbot-Letsencrypt-" + token
            response, validation = achall.response_and_validation()

            http_response_content = validation.encode()
            irule_text = "when HTTP_REQUEST { if {[HTTP::uri] equals {/.well-known/acme-challenge/%s}} { HTTP::respond 200 -version auto content {%s} } }" % (token, http_response_content)

            payload = {}

            payload['kind'] = 'tm:ltm:rule:rulestate'
            payload['partition'] = self.partition
            payload['name'] = irule_name
            payload['apiAnonymous'] = irule_text

            request = self.session.post("https://%s:%d/mgmt/tm/ltm/rule" % (self.host, self.port), data=json.dumps(payload), timeout=4)

            if request.status_code == requests.codes.ok:
                return response
            else:
                return None

        except Exception, e:
            msg = ("iRule creation on {0} failed. {2}{1}{2}".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def delete_irule(self, achall):
        try:
            irule_name = "Certbot-Letsencrypt-" + achall.chall.encode("token")

            request = self.session.delete("https://%s:%d/mgmt/tm/ltm/rule/~%s~%s" % (self.host, self.port, self.partition, irule_name), timeout=4)

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("iRule deletion from {0} failed. {2}{1}{2}".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def exists_virtual(self, virtual_name):
        try:
            request = self.session.get("https://%s:%d/mgmt/tm/ltm/virtual/~%s~%s" % (self.host, self.port, self.partition, virtual_name), timeout=4)

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("Virtual server check on {0} failed. {2}{1}{2}".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def profile_on_virtual(self, virtual_name, profile_type):
        try:
            request = self.session.get("https://%s:%d/mgmt/tm/ltm/virtual/~%s~%s/profiles" % (self.host, self.port, self.partition, virtual_name), timeout=4)

            if request.status_code == requests.codes.ok:
                if 'items' in request.json():
                    for item in request.json()['items']:
                        profile = self.session.get("https://%s:%d/mgmt/tm/ltm/profile/%s/~%s~%s" % (self.host, self.port, profile_type, item['partition'], item['name']), timeout=4)

                        if profile.status_code == requests.codes.ok:
                            return True
                else:
                    return False
            else:
                return False

        except Exception, e:
            msg = ("Test for HTTP profile on virtual server on {0} failed. {2}{1}{2}".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def http_virtual(self, virtual_name):
        return self.profile_on_virtual(virtual_name, 'http')

    def client_ssl_virtual(self, virtual_name):
        return self.profile_on_virtual(virtual_name, 'client-ssl')

    def associate_client_ssl_virtual(self, virtual_name, client_ssl_name):
        try:
            payload = {}

            payload['kind'] = 'tm:ltm:virtual:profiles:profilesstate'
            payload['partition'] = self.partition
            payload['name'] = client_ssl_name
            payload['context'] = 'clientside'

            request = self.session.post("https://%s:%d/mgmt/tm/ltm/virtual/~%s~%s/profiles" % (self.host, self.port, self.partition, virtual_name), json.dumps(payload), timeout=4)

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("Association of client SSL profile to virtual {0} failed. {2}{1}{2}".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def remove_client_ssl_virtual(self, virtual_name, sni):
        try:
            profile_request = self.session.get("https://%s:%d/mgmt/tm/ltm/virtual/~%s~%s/profiles" % (self.host, self.port, self.partition, virtual_name), timeout=4)

            if profile_request.status_code == requests.codes.ok and 'items' in request_json:
                profiles = profile_request.json()

                profile_reference_list = {}

                for profile_reference in profiles['items']:
                    if profile_reference['name'] != self.profile_base_name + "-" + sni:
                        profile_reference_list.append(profile_reference)

                profiles['items'] = profile_reference_list

                remove_profile_request = self.session.patch("https://%s:%d/mgmt/tm/ltm/virtual/~%s~%s/profiles" % (self.host, self.port, self.partition, virtual_name), json.dumps(profiles), timeout=4)

                if remove_profile_request.status_code == requests.codes.ok:
                    return True
                else:
                    return False
            else:
                return False

        except Exception, e:
            msg = ("Removal of client SSL profile on virtual {0} failed. {2}{1}{2}".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def irules_on_virtual(self, virtual_name):
        try:
            request = self.session.get("https://%s:%d/mgmt/tm/ltm/virtual/~%s~%s" % (self.host, self.port, self.partition, virtual_name), timeout=4)

            if request.status_code == requests.codes.ok:
                if 'rules' in request.json():
                    return {'result': True, 'rules': request.json()['rules']}
                else:
                    return {'result': True, 'rules': []}
            else:
                return {'result': False, 'rules': []}

        except Exception, e:
            msg = ("Retrieval of iRules for virtual server on {0} failed. {2}{1}{2}".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def associate_irule_virtual(self, achall, virtual_name):
        try:
            irules = self.irules_on_virtual(virtual_name)

            if irules['result'] != False:
                payload = {}
                payload['rules'] = irules['rules']
                payload['rules'].append("Certbot-Letsencrypt-" + achall.chall.encode("token"))

                request = self.session.patch("https://%s:%d/mgmt/tm/ltm/virtual/~%s~%s" % (self.host, self.port, self.partition, virtual_name), json.dumps(payload), timeout=4)

                if request.status_code == requests.codes.ok:
                    return True
                else:
                    return False
            else:
                return False

        except Exception, e:
            msg = ("iRule association to virtual server on {0} failed. {2}{1}{2}".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)

    def remove_irule_virtual(self, achall, virtual_name):
        try:
            payload = {}
            payload['rules'] = []

            irules = self.irules_on_virtual(virtual_name)
            irule_name_inc_partition = "/%s/%s" % (self.partition, "Certbot-Letsencrypt-" + achall.chall.encode("token"))

            for irule_name in irules['rules']:
                if irule_name != irule_name_inc_partition:
                    payload['rules'].append(irule_name)

            request = self.session.patch("https://%s:%d/mgmt/tm/ltm/virtual/~%s~%s" % (self.host, self.port, self.partition, virtual_name), json.dumps(payload), timeout=4)

            if request.status_code == requests.codes.ok:
                return True
            else:
                return False

        except Exception, e:
            msg = ("iRule removal from virtual server on {0} failed. {2}{1}{2}".format(self.host, e, os.linesep))
            raise errors.AuthorizationError(msg)
