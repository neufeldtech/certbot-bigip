"""Contains UI methods for F5 BIG-IP operations."""
import logging
import os

import zope.component

from certbot import errors
from certbot import interfaces

import certbot.display.util as display_util

logger = logging.getLogger(__name__)

def select_vservers(domain, vservers):
    """Select an appropriate F5 BIG-IP Virtual Server.

    :param vservers: Available F5 BIG-IP Virtual Servers
    :type vservers: :class:`list` of type `~obj.Vserver`

    :returns: VirtualServer or `None`
    :rtype: `~obj.Vserver` or `None`

    """
    if not vservers:
        return None
    while True:
        code, tag = _vserver_menu(domain, vservers)
        if code == display_util.HELP:
            _more_info_vserver(vservers[tag])
        elif code == display_util.OK:
            return vservers[tag]
        else:
            return None


def _vserver_menu(domain, vservers):
    """Select an appropriate F5 BIG-IP Virtual Server.

    :param vservers: Available F5 BIG-IP Virtual Servers
    :type vservers: :class:`list` of type `~obj.Vserver`

    :returns: Display tuple - ('code', tag')
    :rtype: `tuple`

    """
    # Free characters in the line of display text (9 is for ' | ' formatting)
    free_chars = display_util.WIDTH - len("HTTPS") - len("Enabled") - 9

    if free_chars < 2:
        logger.debug("Display size is too small for "
                     "certbot_bigip.display_ops._vserver_menu()")
        # This runs the edge off the screen, but it doesn't cause an "error"
        filename_size = 1
        disp_name_size = 1
    else:
        # Filename is a bit more important and probably longer with 000-*
        filename_size = int(free_chars * .6)
        disp_name_size = free_chars - filename_size

    choices = []
    for vserver in vservers:
        if len(vserver.get_names()) == 1:
            disp_name = next(iter(vserver.get_names()))
        elif len(vserver.get_names()) == 0:
            disp_name = ""
        else:
            disp_name = "Multiple Names"

        choices.append(
            "{fn:{fn_size}s} | {name:{name_size}s} | {https:5s} | "
            "{active:7s}".format(
                fn=os.path.basename(vserver.filep)[:filename_size],
                name=disp_name[:disp_name_size],
                https="HTTPS" if vserver.ssl else "",
                active="Enabled" if vserver.enabled else "",
                fn_size=filename_size,
                name_size=disp_name_size)
        )

    try:
        code, tag = zope.component.getUtility(interfaces.IDisplay).menu(
            "We were unable to find a virtual server with name"
            "{0}.{1}Which virtual server would you "
            "like to choose?\n".format(domain, os.linesep),
            choices, help_label="More Info", ok_label="Select")
    except errors.MissingCommandlineFlag as e:
        msg = ("Failed to run F5 BIG-IP plugin non-interactively{1}{0}{1}"
               "(Login to the F5 BIG-IP devices probably failed".format(e, os.linesep))
        raise errors.MissingCommandlineFlag(msg)

    return code, tag

def _more_info_vserver(vserver):
    zope.component.getUtility(interfaces.IDisplay).notification(
        "Virtual Server Information:{0}{1}{0}{2}".format(
            os.linesep, "-" * (display_util.WIDTH - 4), str(vserver)),
        height=display_util.HEIGHT)
