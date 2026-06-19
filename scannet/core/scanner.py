import time
from typing import Dict, Any, List, Union
from scannet.core.validator import TargetValidator
from scannet.core.port_scanner import PortScanner
from scannet.core.service_detector import ServiceDetector
from scannet.core.os_detector import OSDetector
from scannet.core.dns_tools import DNSTools
from scannet.core.whois_tools import WHOISTools
from scannet.core.traceroute import Traceroute
from scannet.utils.config import ScanConfig, ScanProfile
from scannet.utils.helpers import parse_ports
from scannet.utils.logger import get_logger

logger = get_logger()

class NetScanner:
    def __init__(
        self,
        target: str,
        timeout: float = 2.0,
        threads: int = 20,
        rate_limit: int = 0,
        allow_public: bool = False,
        authorized: bool = False,
        profile: str = "normal"
    ):
        self.target = target
        self.config = ScanConfig(
            timeout=timeout,
            threads=threads,
            rate_limit=rate_limit,
            allow_public=allow_public,
            authorized=authorized,
            profile=ScanProfile(profile)
        )
        self.config.apply_profile()
        
        # Validate target immediately
        self.resolved_ip = TargetValidator.validate_target(
            target=self.target,
            allow_public=self.config.allow_public,
            authorized=self.config.authorized
        )

    def scan_ports(self, ports_input: Union[str, List[int]], scan_type: str = "tcp", detect_services: bool = False, detect_os: bool = False) -> Dict[str, Any]:
        """Runs port scanning on the configured target."""
        start_time = time.time()
        
        # Parse ports
        if isinstance(ports_input, str):
            ports = parse_ports(ports_input)
        else:
            ports = ports_input

        # Port scanning
        scanner = PortScanner(
            target=self.resolved_ip,
            timeout=self.config.timeout,
            threads=self.config.threads,
            rate_limit=self.config.rate_limit
        )
        scan_results = scanner.scan_ports(ports, scan_type=scan_type)
        
        # Service detection
        if detect_services:
            detector = ServiceDetector(target=self.resolved_ip, timeout=self.config.timeout)
            for port in list(scan_results.keys()):
                logger.info(f"Detecting service banner on port {port}...")
                det = detector.detect_service(port)
                scan_results[port].update(det)

        # OS detection
        os_est = "Unknown"
        if detect_os:
            logger.info(f"Running OS detection on host {self.target}...")
            ttl = OSDetector.get_ttl_for_host(self.resolved_ip)
            banners = [info.get("banner", "") for info in scan_results.values() if "banner" in info]
            os_est = OSDetector.estimate_os(ttl, list(scan_results.keys()), banners)

        end_time = time.time()
        duration = end_time - start_time
        
        # Build standard output model
        report_data = {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "hosts": {
                self.resolved_ip: {
                    "hostname": DNSTools.reverse_lookup(self.resolved_ip),
                    "os_estimation": os_est if detect_os else None,
                    "ports": scan_results
                }
            },
            "summary": {
                "scan_duration": duration,
                "active_hosts": 1,
                "open_ports": len(scan_results)
            }
        }
        
        return report_data
        
    def run_full_scan(self, ports_input: Union[str, List[int]]) -> Dict[str, Any]:
        """Runs port scan, service discovery, and OS fingerprinting altogether."""
        return self.scan_ports(ports_input, detect_services=True, detect_os=True)
