import subprocess
import re
from . import const

class WiFiUtilError(Exception):
    pass

def wifi_scan_networks():
    """扫描可用的 WiFi 网络"""
    try:
        cmd = ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s']
        output = subprocess.check_output(cmd, universal_newlines=True)
        networks = []
        
        for line in output.split('\n')[1:]:  # Skip header line
            if line.strip():
                fields = re.split('\s+', line.strip())
                if len(fields) >= 2:
                    networks.append({
                        'ssid': fields[0],
                        'signal': fields[2],
                        'security': fields[6] if len(fields) > 6 else 'NONE'
                    })
        return networks
    except Exception as e:
        raise WiFiUtilError(f"Error scanning networks: {str(e)}")

def wifi_connect(ssid, password):
    """连接到指定的 WiFi 网络"""
    try:
        cmd = ['networksetup', '-setairportnetwork', 'en0', ssid, password]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return True
        return False
    except Exception as e:
        raise WiFiUtilError(f"Error connecting to network: {str(e)}")

def wifi_disconnect():
    """断开当前 WiFi 连接"""
    try:
        cmd = ['networksetup', '-setairportpower', 'en0', 'off']
        subprocess.run(cmd, check=True)
        cmd = ['networksetup', '-setairportpower', 'en0', 'on']
        subprocess.run(cmd, check=True)
        return True
    except Exception as e:
        raise WiFiUtilError(f"Error disconnecting: {str(e)}")

def wifi_get_interfaces():
    """获取可用的 WiFi 接口"""
    try:
        cmd = ['networksetup', '-listallhardwareports']
        output = subprocess.check_output(cmd, universal_newlines=True)
        interfaces = []
        
        for line in output.split('\n'):
            if 'Wi-Fi' in line:
                device = next((l for l in output.split('\n') if 'Device' in l), None)
                if device:
                    interface = device.split(': ')[1]
                    interfaces.append(interface)
        
        return interfaces
    except Exception as e:
        raise WiFiUtilError(f"Error getting interfaces: {str(e)}")

# macOS specific constants
display_str_to_key = {
    'WPA': const.AKM_TYPE_WPA,
    'WPA2': const.AKM_TYPE_WPA2,
    'WPA3': const.AKM_TYPE_WPA3,
    'NONE': const.AKM_TYPE_NONE
}