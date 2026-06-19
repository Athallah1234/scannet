from scannet.protocols.icmp import icmp_ping
from scannet.protocols.tcp import tcp_connect
from scannet.protocols.udp import udp_ping
import socket
import os
import platform
import subprocess

class PingTools:
    @staticmethod
    def ping_icmp(host: str, timeout: float = 2.0) -> bool:
        return icmp_ping(host, timeout)

    @staticmethod
    def ping_tcp(host: str, port: int = 80, timeout: float = 2.0) -> bool:
        return tcp_connect(host, port, timeout)

    @staticmethod
    def ping_udp(host: str, port: int = 123, timeout: float = 2.0) -> bool:
        return udp_ping(host, port, timeout)

    @staticmethod
    def arp_scan_local(host: str, timeout: float = 2.0) -> bool:
        """
        Runs simple ARP resolution check for local systems if possible.
        Actually, we can parse ARP cache using 'arp -a' to see if IP resides in local neighborhood.
        """
        try:
            # Query ARP table
            if platform.system().lower() == "windows":
                output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
            else:
                output = subprocess.check_output(["arp", "-n"], text=True, stderr=subprocess.DEVNULL)
                
            return host in output
        except Exception:
            return False
