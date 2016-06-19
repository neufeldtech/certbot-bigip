"""F5 BIG-IP plugin constants."""
import pkg_resources

from certbot import util

HSTS_IRULE = ''

CLI_DEFAULTS = dict(
    bigip_list = None,
    bigip_username = None,
    bigip_password = None,
    bigip_password_env = None,
    bigip_password_file = None,
    bigip_partition = 'Common',
    bigip_ciphers = None,
    bigip_ciphers_best = '',
    bigip_clientssl_parent = '/Common/clientssl',
    virtual_server_list = None,
)
