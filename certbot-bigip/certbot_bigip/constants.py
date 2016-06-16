"""F5 BIG-IP plugin constants."""
import pkg_resources

from certbot import util

HSTS_IRULE = ''

CLI_DEFAULTS = dict(
    bigip_list = '',
    bigip_username = 'admin',
    bigip_password = 'password',
    bigip_partition = 'Common',
    virtual_server_list = '',
)
