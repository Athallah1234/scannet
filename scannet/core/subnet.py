import ipaddress
from typing import Dict, Any, List

class SubnetTools:
    @staticmethod
    def get_subnet_info(cidr: str) -> Dict[str, Any]:
        """Calculates subnet properties and metadata."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            return {
                "cidr": cidr,
                "network_address": str(net.network_address),
                "broadcast_address": str(net.broadcast_address),
                "netmask": str(net.netmask),
                "total_hosts": net.num_addresses,
                "usable_hosts": max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses,
                "is_private": net.is_private,
                "is_loopback": net.is_loopback,
                "is_multicast": net.is_multicast,
                "is_reserved": net.is_reserved,
            }
        except ValueError as e:
            raise ValueError(f"Invalid CIDR subnet representation: {e}")

    @staticmethod
    def get_hosts(cidr: str) -> List[str]:
        """Lists all usable host IPs in a CIDR subnet."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            # For large ranges limit to /24 to prevent memory issues unless user accepts
            if net.prefixlen < 16:
                raise ValueError("Subnets larger than /16 are blocked to prevent memory issues.")
            
            # For /31 and /32 networks all IPs are usable
            if net.prefixlen >= 31:
                return [str(ip) for ip in net]
            return [str(ip) for ip in net.hosts()]
        except ValueError as e:
            raise ValueError(str(e))
        
    @staticmethod
    def check_ip_attributes(ip_str: str) -> Dict[str, bool]:
        """Verifies properties of an individual IP address."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return {
                "is_private": ip.is_private,
                "is_loopback": ip.is_loopback,
                "is_multicast": ip.is_multicast,
                "is_reserved": ip.is_reserved,
                "is_global": ip.is_global,
                "is_link_local": ip.is_link_local
            }
        except ValueError:
            return {}
