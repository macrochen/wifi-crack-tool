#!/usr/bin/env python3
# vim: set fileencoding=utf-8

"""Define WiFi Profile."""

from .const import *

class Profile:
    """WiFi Profile."""

    def __init__(self):
        # 初始化时直接设置默认值，而不是 None
        self.id = 0
        self.auth = AUTH_ALG_OPEN
        self.akm = AKM_TYPE_WPA2PSK  # 设置默认值为 WPA2PSK
        self.cipher = CIPHER_TYPE_CCMP
        self.ssid = None
        self.bssid = None
        self.key = None
        self.signal = 0

    def __eq__(self, profile):
        """比较两个配置文件是否相同"""
        if not isinstance(profile, Profile):
            return False

        if profile.ssid and profile.ssid != self.ssid:
            return False

        if profile.bssid and profile.bssid != self.bssid:
            return False

        if profile.auth and profile.auth != self.auth:
            return False

        if profile.cipher and profile.cipher != self.cipher:
            return False

        if profile.akm and profile.akm != self.akm:
            return False

        return True

    def __str__(self):
        """返回配置文件的字符串表示"""
        return f"Profile(ssid='{self.ssid}', auth={self.auth}, akm={self.akm}, cipher={self.cipher})"
