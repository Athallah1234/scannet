from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from scannet.core.subnet import SubnetTools
from scannet.core.ping import PingTools
from scannet.utils.rate_limiter import RateLimiter
from scannet.utils.logger import get_logger
from scannet.core.validator import TargetValidator

logger = get_logger()

class HostDiscovery:
    def __init__(self, subnet: str, timeout: float = 2.0, threads: int = 20, rate_limit: int = 0, allow_public: bool = False, authorized: bool = False):
        self.subnet = subnet
        self.timeout = timeout
        self.threads = min(threads, 100) # Max limit 100
        self.rate_limiter = RateLimiter(rate_limit)
        self.allow_public = allow_public
        self.authorized = authorized
        
    def discover(self) -> List[str]:
        """Discovers active hosts on the configured subnet using ICMP, TCP (80, 443), UDP and ARP table checks."""
        # Validate target
        TargetValidator.validate_target(self.subnet, self.allow_public, self.authorized)
        
        try:
            hosts = SubnetTools.get_hosts(self.subnet)
        except ValueError as e:
            logger.error(f"Error parsing subnet: {e}")
            return []
            
        active_hosts = []
        logger.info(f"Starting host discovery sweep on subnet {self.subnet} ({len(hosts)} hosts) with {self.threads} threads...")
        
        def check_host(ip: str) -> str:
            self.rate_limiter.limit()
            
            # 1. Local ARP check
            if PingTools.arp_scan_local(ip, self.timeout):
                return ip
            # 2. ICMP Ping
            if PingTools.ping_icmp(ip, self.timeout):
                return ip
            # 3. TCP Handshake on Common Ports
            for port in [80, 443, 22, 135, 445]:
                if PingTools.ping_tcp(ip, port, self.timeout):
                    return ip
            # 4. UDP Ping
            if PingTools.ping_udp(ip, 137, self.timeout) or PingTools.ping_udp(ip, 123, self.timeout):
                return ip
                
            return ""

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(check_host, ip): ip for ip in hosts}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        active_hosts.append(result)
                        logger.info(f"Host Active: {result}")
                except Exception as e:
                    logger.debug(f"Error checking host {ip}: {e}")
                    
        return sorted(active_hosts)
        
class NetworkDiscovery:
    """Wrapper class conforming to requested python API sample."""
    def __init__(self, subnet: str, authorized: bool = False, allow_public: bool = False, timeout: float = 2.0, threads: int = 20):
        self.subnet = subnet
        self.authorized = authorized
        self.allow_public = allow_public
        self.timeout = timeout
        self.threads = threads
        
    def discover(self) -> List[str]:
        discovery = HostDiscovery(
            subnet=self.subnet,
            timeout=self.timeout,
            threads=self.threads,
            allow_public=self.allow_public,
            authorized=self.authorized
        )
        return discovery.discover()
