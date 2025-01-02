#!/usr/bin/env python3
# vim: set fileencoding=utf-8

"""Implement wifi management."""

import logging
import platform
from .iface import Interface

system = platform.system()

if system == 'Windows':
    from .win import wifiutil
elif system == 'Linux':
    from .linux import wifiutil
elif system == 'Darwin':  # macOS
    from .darwin import wifiutil
else:
    raise NotImplementedError("Platform {} is not supported.".format(system))

class PyWiFi:
    """PyWiFi provides methods for manipulating wifi devices."""

    def __init__(self):
        self._logger = logging.getLogger('pywifi')
        self._ifaces = []
        self._interfaces = wifiutil.get_interfaces()

    def interfaces(self):
        """Get wifi interfaces."""
        interfaces = []
        for iface_id in self._interfaces:
            interfaces.append(Interface(self, iface_id))
        return interfaces
