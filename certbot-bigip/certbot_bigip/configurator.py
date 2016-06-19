"""Certbot Bigip plugin."""

import zope.component
import zope.interface

from acme import challenges

from certbot import errors
from certbot import interfaces
from certbot import reverter
from certbot import util

from certbot.plugins import common

from certbot_bigip import constants
from certbot_bigip import display_ops
from certbot_bigip import tls_sni_01
from certbot_bigip import obj

from certbot.plugins import common

from collections import defaultdict

from icontrol.session import iControlRESTSession

import os
import logging
import random
import string

logger = logging.getLogger(__name__)

# Define a helper function to avoid verbose code
z_util = zope.component.getUtility

@zope.interface.implementer(interfaces.IAuthenticator, interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class BigipConfigurator(common.Plugin):
    """F5 BIG-IP Configurator"""

    description = "F5 BIG-IP - currently doesn't work"

    @classmethod
    def add_parser_arguments(cls, add):
        add("list", default=constants.CLI_DEFAULTS["bigip_list"],
            help="CSV list of BIG-IP system hostnames or addresses")
        add("username", default=constants.CLI_DEFAULTS["bigip_username"],
            help="BIG-IP username (common to all listed BIG-IP systems)")
        add("password", default=constants.CLI_DEFAULTS["bigip_password"],
            help="BIG-IP password (common to all listed BIG-IP systems)")
        add("partition", default=constants.CLI_DEFAULTS["bigip_partition"],
            help="BIG-IP partition (common to all listed BIG-IP systems)")
        add("vs-list", default=constants.CLI_DEFAULTS["virtual_server_list"],
            help="CSV list of BIG-IP virtual server names, optionally including partition")

    def __init__(self, *args, **kwargs):
        """Initialize an F5 BIG-IP Configurator"""

        version = kwargs.pop("version", None)
        super(BigipConfigurator, self).__init__(*args, **kwargs)

        # Add name_server association dict
        self.assoc = dict()
        # Outstanding challenges
        self._chall_out = set()
        # Maps enhancements to vhosts we've enabled the enhancement for
        self._enhanced_vhosts = defaultdict(set)

        self.bigip_list = []
        self.bigip_vs_list = []

        self.version = version
        self.vservers = None
        self._enhance_func = { }

        # self.reverter = reverter.Reverter(self.config)

    def prepare(self):
        """Prepare the authenticator/installer"""

        if self.conf('username') == '':
            msg = ("No username specified, please use --bigip-username")
            raise errors.MissingCommandlineFlag(msg)

        if self.conf('password') == '':
            msg = ("No password specified, please use --bigip-password")
            raise errors.MissingCommandlineFlag(msg)

        if self.conf('vs_list') != '':
            self.bigip_vs_list = self.conf('vs_list').split(',')
        else:
            msg = ("--bigip-vs-list is required when using the F5 BIG-IP plugin")
            raise errors.MissingCommandlineFlag(msg)

        if self.conf('list') != '':
            bigip_host_list = self.conf('list').split(',')
            for bigip_host in bigip_host_list:
                bigip = obj.Bigip(bigip_host, 443, self.conf('username'), self.conf('password'), self.conf('partition'), False)

                if bigip.test() == False:
                    if len(bigip_host_list) > 1:
                        response = z_util(interfaces.IDisplay).yesno(
                            "Could not connect or authenticate to F5 BIG-IP {0}{1}{1}"
                            "Would like to continue attempting to connect to the rest "
                            "of the F5 BIG-IP's in the list?".format(bigip_host, os.linesep),
                            default=True)

                        if response == False:
                            return
                    else:
                        msg = "Could not connect or authenticate to F5 BIG-IP %s" % bigip_host
                        raise errors.AuthorizationError(msg)
                else:
                    self.bigip_list.append(bigip)

    def config_test(self):

        print "DEBUG: in config_test()"

        return

    def more_info(self):
        """Human-readable string to help understand the module"""

        return (
            "Configures F5 BIG-IP to authenticate and configure X.509"
            "certificate/key use"
        )

    def get_chall_pref(self, domain):
        """Return list of challenge preferences."""

        return [challenges.HTTP01]
        # TODO: support TLSSNI01
        # return [challenges.TLSSNI01]

    def perform(self, achalls):
        """Perform the configuration related challenge.

        This function currently assumes all challenges will be fulfilled.
        If this turns out not to be the case in the future. Cleanup and
        outstanding challenges will have to be designed better.

        """

        responses = [None] * len(achalls)

        tlssni01_chall_doer = tls_sni_01.BigipTlsSni01(self)

        count = 0
        for achall in achalls:
            if isinstance(achall.chall, challenges.HTTP01):

                for bigip in self.bigip_list:
                    response = bigip.create_irule_HTTP01(achall)

                    for virtual_server in self.bigip_vs_list:
                        responses[count] = response

                        if bigip.exists_virtual(virtual_server) and bigip.http_virtual(virtual_server):
                            # virtual server exists and has a HTTP profile attached to it
                            # associate the iRule to it which will respond for HTTP01 validations
                            bigip.associate_irule_virtual(achall, virtual_server)

            else: # TLSSNI01
                for bigip in self.bigip_list:
                    for virtual_server in self.bigip_vs_list:
                        response = tlssni01_chall_doer.perform(achall)

                        responses[count] = response

                        if bigip.exists_virtual(virtual_server) and bigip.http_virtual(virtual_server) and bigip.client_ssl_virtual(virtual_server):
                            client_ssl_name = "Certbot-LetsEncrypt-%s" % challenge.response(challenge.account_key).z_domain

                            bigip.create_client_ssl_profile(client_ssl_name, 'default.crt', 'default.key', None, challenge.response(challenge.account_key).z_domain)

                            bigip.associate_client_ssl_virtual(virtual_server, client_ssl_name)

            ++count

        return responses

    def cleanup(self, achalls):
        """Revert all challenges."""

        for achall in achalls:
            if isinstance(achall.chall, challenges.HTTP01):
                for bigip in self.bigip_list:
                    for virtual_server in self.bigip_vs_list:
                        if bigip.exists_virtual(virtual_server):
                            if bigip.remove_irule_virtual(achall, virtual_server) == True:
                                bigip.delete_irule(achall)
                            else:
                                print "ERROR: iRule could not be removed from virtual server '%s' you may need to do this manually" % virtual_server
                        else:
                            print "ERROR: The virtual server '%s' does not appear to exist on this BIG-IP" % virtual_server
            else: # TLSSNI01
                print "FIX ME"

        return

    def get_all_names(self):
        """Cannot currently work for F5 BIG-IP due to the way in which Cerbot validates
        returned strings as conforming to host/domain name format. e.g. F5 BIG-IP virtual
        server names are not always in pure host/domain name.

        :raises errors.PluginError: Always

        """

        msg = ("Certbot can't be used to select domain names based on F5 "
               "BIG-IP Virtual Server names.{0}{0}Please use CLI arguments, "
               "example: --bigip-vs-list virtual_name1,virtual_name2 --domain "
               "domain.name".format(os.linesep))

        raise errors.PluginError(msg)

    def deploy_cert(self, domain, cert_path, key_path, chain_path=None, fullchain_path=None):
        """Deploys certificate and key to specified F5 BIG-IP, creates or updates
        client SSL profiles, and ensures they are associated with the specified
        virtual server.

        :raises errors.PluginError: When unable to deploy certificate due to
            a lack of directives

        """

        for bigip in self.bigip_list:
            # install cert/key/chain/fullchain
            cert_name = "Certbot-Letsencrypt-%s.crt" % domain
            key_name = "Certbot-Letsencrypt-%s.key" % domain
            chain_name = "Certbot-Letsencrypt-%s-chain.crt" % domain
            fullchain_name = "Certbot-Letsencrypt-%s-fullchain.crt" % domain
            client_ssl_name = "Certbot-Letsencrypt-%s" % domain

            bigip.upload_file(cert_path, cert_name)
            bigip.create_crypto_cert(cert_name, cert_name)

            bigip.upload_file(key_path, key_name)
            bigip.create_crypto_key(key_name, key_name)

            bigip.upload_file(chain_path, chain_name)
            bigip.create_crypto_cert(chain_name, chain_name)

            # bigip.upload_file(fullchain_path, fullchain_name)
            # bigip.create_crypto_cert(fullchain_name, fullchain_name)

            # search for existing client SSL profiles which match: Certbot-Letsencrypt-%{DOMAIN} AND have SNI name = %{DOMAIN}
            # if no matching client SSL profiles create profiles for certificate primary name and all alternative names

            bigip.create_client_ssl_profile(client_ssl_name, cert_name, key_name, chain_name, domain)

            for virtual_server in self.bigip_vs_list:
                if bigip.client_ssl_virtual(virtual_server) == True:
                    bigip.associate_client_ssl_virtual(virtual_server, client_ssl_name)

        return

    def enhance(self, domain, enhancement, options=None):
        """Enhance configuration.

        :param str domain: domain to enhance
        :param str enhancement: enhancement type defined in
            :const:`~certbot.constants.ENHANCEMENTS`
        :param options: options for the enhancement
            See :const:`~certbot.constants.ENHANCEMENTS`
            documentation for appropriate parameter.

        :raises .errors.PluginError: If Enhancement is not supported, or if
            there is any other problem with the enhancement.

        """

        return

    def supported_enhancements(self): # pylint: disable=no-self-use
        """Returns currently supported enhancements."""

        # TODO:
        #  1. convert-to-https - Convert HTTP virtual to HTTPS virtual
        #  2. clone-to-https - Clone HTTP virtual to HTTPS virtual
        #  3. redirect - Apply _sys_http_redirect iRule to HTTP virtuals
        #  4. staple-ocsp - Configure OCSP stapling
        #  5. http-sts - Configure HTTP Strict Transport Security
        #  6. http-pkp - Configure HTTP Public Key Pinning
        #  7. best-practice - Configure best practice ciphers and other items at time of use (if code is up to date)

        # Currently can't do any of those...

        return []

    def get_all_certs_keys(self):

        print "DEBUG: in get_all_certs_keys()"

        return []

    def save(self, title=None, temporary=False):
        """Saves all changes to all F5 BIG-IP's, e.g. tmsh /sys save config.

        This function first checks for save errors, if none are found,
        all configuration changes made will be saved. According to the
        function parameters. If an exception is raised, a new checkpoint
        was not created.

        :param str title: The title of the save. If a title is given, a UCS
            archive will be created.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (ie. challenges)

        :raises .errors.PluginError: If there was an error in Augeas, in
            an attempt to save the configuration, or an error creating a
            checkpoint
        """

        for bigip in self.bigip_list:
            if title != None:
                ucs = title + ".ucs"
                bigip.save_ucs(ucs)

            if temporary == False:
                bigip.save()

        return

    def revert_challenge_config(self):

        print "DEBUG: in revert_challenge_config()"

        return

    def rollback_checkpoints(self, rollback=1):

        print "DEBUG: in rollback_checkpoints()"

        return

    def recovery_routine(self):

        print "DEBUG: in recovery_routine()"

        return

    def view_config_changes(self):

        print "DEBUG: in view_config_changes()"

        return

    def restart(self):
        """Does nothing in context of F5 BIG-IP, but must be defined.

        """

        return
