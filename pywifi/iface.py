#!/usr/bin/env python3
# vim: set fileencoding=utf-8

"""Interface for manipulating wifi devies."""

import logging
import platform
from .const import *

system = platform.system()

if system == 'Windows':
    from .win import wifiutil
elif system == 'Linux':
    from .linux import wifiutil
elif system == 'Darwin':  # macOS
    from .darwin import wifiutil
else:
    raise NotImplementedError("Platform {} is not supported.".format(system))

class Interface:
    """Interface provides methods for manipulating wifi devices."""

    def __init__(self, wifi_instance, iface_id):
        self._wifi_instance = wifi_instance
        self._iface_id = iface_id
        self._status = IFACE_DISCONNECTED
        self._logger = logging.getLogger('pywifi')
        self._current_profile = None

    def name(self):
        """Get interface name."""
        return self._iface_id

    def scan(self):
        """Trigger scan."""
        try:
            self._status = IFACE_SCANNING
            result = wifiutil.scan(self._iface_id)
            self._status = IFACE_DISCONNECTED
            return result
        except Exception as e:
            self._logger.error(f"Scan error: {e}")
            self._status = IFACE_DISCONNECTED
            return False

    def scan_results(self):
        """Get scan results."""
        try:
            return wifiutil.scan_results(self._iface_id)
        except Exception as e:
            self._logger.error(f"Scan results error: {e}")
            return []

    def disconnect(self):
        """Disconnect."""
        try:
            self._status = IFACE_DISCONNECTED
            self._current_profile = None
            return wifiutil.disconnect(self._iface_id)
        except Exception as e:
            self._logger.error(f"Disconnect error: {e}")
            return False

    def connect(self, profile):
        """Connect to specified AP."""
        try:
            self._status = IFACE_CONNECTING
            self._current_profile = profile
            result = wifiutil.connect(self._iface_id, profile)
            if result:
                self._status = IFACE_CONNECTED
            else:
                self._status = IFACE_DISCONNECTED
                self._current_profile = None
            return result
        except Exception as e:
            self._logger.error(f"Connect error: {e}")
            self._status = IFACE_DISCONNECTED
            self._current_profile = None
            return False

    def status(self):
        """Get interface status."""
        try:
            if self._status == IFACE_CONNECTED and self._current_profile:
                # 验证当前连接状态
                current_status = wifiutil.get_status(self._iface_id)
                if current_status != IFACE_CONNECTED:
                    self._status = IFACE_DISCONNECTED
                    self._current_profile = None
            return self._status
        except Exception as e:
            self._logger.error(f"Get status error: {e}")
            return IFACE_DISCONNECTED

    def remove_all_network_profiles(self):
        """Remove all saved profiles."""
        try:
            return wifiutil.remove_all_profiles(self._iface_id)
        except Exception as e:
            self._logger.error(f"Remove profiles error: {e}")
            return False
