from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Set
from scannet.protocols.tcp import tcp_connect
from scannet.protocols.udp import udp_ping
from scannet.utils.rate_limiter import RateLimiter
from scannet.utils.logger import get_logger
from scannet.utils.config import ScanConfig

logger = get_logger()

class PortScanner:
    def __init__(self, target: str, timeout: float = 2.0, threads: int = 20, rate_limit: int = 0):
        self.target = target
        self.timeout = timeout
        self.threads = min(threads, 100)
        self.rate_limiter = RateLimiter(rate_limit)

    def scan_ports(self, ports: List[int], scan_type: str = "tcp") -> Dict[int, Dict[str, Any]]:
        """Scans specified list of ports on the target using TCP or UDP."""
        results = {}
        logger.info(f"Starting {scan_type.upper()} port scan on {self.target} ({len(ports)} ports) with {self.threads} threads...")
        
        def scan_single(port: int) -> Dict[str, Any]:
            self.rate_limiter.limit()
            if scan_type.lower() == "tcp":
                is_open = tcp_connect(self.target, port, self.timeout)
                # Simple logic: if connected, open. Else, closed.
                # In connect scan, filtered is hard to distinguish from closed without raw SYN packets,
                # but we can flag timeout or connection refused if we want to differentiate:
                # However, for TCP Connect: Open (Success), Closed/Filtered (Failure)
                return {"port": port, "state": "open" if is_open else "closed"}
            else:
                # UDP scan
                # If udp_ping returns False, it received ICMP Unreachable -> port is Closed.
                # If it times out or gets no error, it might be open or filtered -> open|filtered.
                is_active = udp_ping(self.target, port, self.timeout)
                return {"port": port, "state": "open|filtered" if is_active else "closed"}

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(scan_single, port): port for port in ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    res = future.result()
                    if res["state"] in ["open", "open|filtered"]:
                        results[port] = {"state": res["state"]}
                        logger.info(f"Port {port}: {res['state']}")
                except Exception as e:
                    logger.debug(f"Error scanning port {port}: {e}")
                    
        return results
