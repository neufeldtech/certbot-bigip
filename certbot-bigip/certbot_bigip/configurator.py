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

from certbot.plugins import common

from collections import defaultdict

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

        # These will be set in the prepare function
        self.parser = None
        self.version = version
        self.vhosts = None
        self._enhance_func = { }

        self.reverter = reverter.Reverter(self.config)

    def prepare(self):
        """Prepare the authenticator/installer"""

        # Make sure configuration is valid
        self.config_test()

    def more_info(self):
        """Human-readable string to help understand the module"""
        return (
            "Configures F5 BIG-IP to authenticate and configure X.509"
            "certificate/key use"
        )

    def get_chall_pref(self, domain):
        """Return list of challenge preferences."""
        return [challenges.TLSSNI01]

    def perform(self, achalls):
        responses = [None] * len(achalls)
        chall_doer = tls_sni_01.BigipTlsSni01(self)

        for i, achall in enumerate(achalls):
            print "Authentication Challenge %s: %s" % (i, achall)
            # Currently also have chall_doer hold associated index of the
            # challenge. This helps to put all of the responses back together
            # when they are all complete.
            chall_doer.add_chall(achall, i)

        sni_response = chall_doer.perform()

        print "SNI Response: %s" % sni_response

        if sni_response:
            # Go through all of the challenges and assign them to the proper
            # place in the responses return value. All responses must be in the
            # same order as the original challenges.
            for i, resp in enumerate(sni_response):
                responses[chall_doer.indices[i]] = resp

        return responses

    def cleanup(self, achalls):
        return

    def get_all_names(self):
        all_names = set()
        all_names.add('VHOST-Example-1')
        return []

    def deploy_cert(self, domain, cert_path, key_path, chain_path, fullchain_path):
        return

    def enhance(self, domain, enhancement, options=None):
        return

    def supported_enhancements(self):
        """Returns currently supported enhancements."""
        return []

    def get_all_certs_keys(self):
        return []

    def save(self, title=None, temporary=False):
        return

    def revert_challenge_config(self):
        return

    def rollback_checkpoints(self, rollback=1):
        return

    def recovery_routine(self):
        return

    def view_config_changes(self):
        return

    def config_test(self):
        return

    def restart(self):
        return
