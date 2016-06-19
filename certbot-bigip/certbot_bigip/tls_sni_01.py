"""A class that performs TLS-SNI-01 challenges for F5 BIG-IP"""

import os
import logging

from certbot.plugins import common
from certbot.errors import PluginError, MissingCommandlineFlag

logger = logging.getLogger(__name__)

class BigipTlsSni01(common.TLSSNI01):
    """Class that performs TLS-SNI-01 challenges within the F5 BIG-IP configurator

    :ivar configurator: BigipConfigurator object
    :type configurator: :class:`~bigip.configurator.BigipConfigurator`

    :ivar list achalls: Annotated TLS-SNI-01
        (`.KeyAuthorizationAnnotatedChallenge`) challenges.

    :param list indices: Meant to hold indices of challenges in a
        larger array. BigipTlsSni01 is capable of solving many challenges
        at once which causes an indexing issue within BigipConfigurator
        who must return all responses in order.  Imagine BigipConfigurator
        maintaining state about where all of the http-01 Challenges,
        TLS-SNI-01 Challenges belong in the response array.  This is an
        optional utility.

    """

    def __init__(self, *args, **kwargs):
        super(BigipTlsSni01, self).__init__(*args, **kwargs)

    def perform(self, achall):
        """Perform a TLS-SNI-01 challenge."""

        response = self._setup_challenge_cert(achall)

        return response
