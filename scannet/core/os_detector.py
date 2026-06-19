import socket
from typing import Dict, Any, List

class OSDetector:
    @staticmethod
    def estimate_os(ttl: int, open_ports: List[int], banners: List[str]) -> str:
        """
        Estimates the OS of a host based on:
        - TTL (Time To Live) typical initial values:
            - Linux/Unix: 64
            - Windows: 128
            - Cisco/Network: 255
        - Listening port patterns (e.g. 135/445/3389 strongly suggests Windows, 22/111 suggests Linux)
        - Service banners (e.g. Apache, Microsoft-IIS, OpenSSH)
        """
        if not ttl and not open_ports and not banners:
            return "Unknown OS"
            
        windows_score = 0
        linux_score = 0
        network_score = 0
        
        # TTL heuristics
        if ttl:
            # TTL will decrease by hop count. We guess the initial TTL.
            if 0 < ttl <= 64:
                linux_score += 3
            elif 64 < ttl <= 128:
                windows_score += 3
            elif 128 < ttl <= 255:
                network_score += 3
                
        # Port patterns
        for p in open_ports:
            if p in [135, 139, 445, 3389]:
                windows_score += 4
            if p in [22, 111, 2049]:
                linux_score += 2
                
        # Banner heuristics
        for banner in banners:
            b_lower = banner.lower()
            if "windows" in b_lower or "iis" in b_lower or "microsoft" in b_lower:
                windows_score += 5
            if "ubuntu" in b_lower or "debian" in b_lower or "redhat" in b_lower or "linux" in b_lower:
                linux_score += 5
            if "cisco" in b_lower or "router" in b_lower or "switch" in b_lower:
                network_score += 5

        # Select maximum score
        if windows_score > linux_score and windows_score > network_score:
            return f"Windows (Estimated, score={windows_score})"
        elif linux_score > windows_score and linux_score > network_score:
            return f"Linux/Unix (Estimated, score={linux_score})"
        elif network_score > 0:
            return f"Network Device / Cisco (Estimated, score={network_score})"
            
        return "Generic OS (Estimated)"
        
    @staticmethod
    def get_ttl_for_host(host: str) -> int:
        """Determines TTL of the host by creating a UDP connection or pinging."""
        # Simple method: use raw socket or just extract from subprocess ping output if available.
        # Since we use subprocess ping in protocols/icmp.py, let's parse TTL if possible.
        import platform
        import subprocess
        import re
        
        cmd = []
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", host]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", host]
            
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            # Find ttl=XX or TTL=XX in output
            match = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return 0
