import socket
import os
import platform
import subprocess
import re
from typing import List, Dict, Any

class Traceroute:
    @staticmethod
    def trace(target: str, max_hops: int = 30, timeout: float = 2.0) -> List[Dict[str, Any]]:
        """
        Traces route to destination using native OS tools to avoid raw socket privilege limitations.
        """
        hops = []
        is_windows = platform.system().lower() == "windows"
        
        if is_windows:
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), target]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout), target]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            hop_num = 1
            for line in iter(process.stdout.readline, ""):
                line = line.strip()
                if not line:
                    continue
                    
                # Match IP addresses or hostnames in the line
                # Example windows:   1    <1 ms    <1 ms    <1 ms  192.168.1.1
                # Example linux: 1  192.168.1.1  0.231 ms
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if ip_match:
                    ip = ip_match.group(1)
                    # Extract latency
                    ms_matches = re.findall(r"(\d+(?:\.\d+)?)\s*ms", line)
                    rtt = f"{ms_matches[0]} ms" if ms_matches else "*"
                    
                    hops.append({
                        "hop": hop_num,
                        "ip": ip,
                        "rtt": rtt
                    })
                    hop_num += 1
                elif "*" in line:
                    hops.append({
                        "hop": hop_num,
                        "ip": "*",
                        "rtt": "*"
                    })
                    hop_num += 1
                    
            process.stdout.close()
            process.wait()
            
        except Exception as e:
            # Fallback mock/simulated hops if traceroute command doesn't exist
            hops.append({
                "hop": 1,
                "ip": "Command unavailable or failed",
                "rtt": str(e)
            })
            
        return hops
