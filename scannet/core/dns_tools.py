import dns.resolver
import socket
from typing import Dict, Any, List

class DNSTools:
    @staticmethod
    def lookup(domain: str) -> Dict[str, Any]:
        """Runs standard DNS resolution queries for common record types."""
        results = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                results[rtype] = [str(r) for r in answers]
            except Exception:
                results[rtype] = []
        return results

    @staticmethod
    def reverse_lookup(ip_address: str) -> str:
        """Finds hostname of an IP address using PTR query."""
        try:
            name, alias, addresslist = socket.gethostbyaddr(ip_address)
            return name
        except Exception:
            return ""

    @staticmethod
    def check_subdomains(domain: str, subdomain_list: List[str]) -> List[Dict[str, str]]:
        """Checks subdomain list for existence without aggressive brute force."""
        discovered = []
        for sub in subdomain_list:
            target = f"{sub.strip()}.{domain}"
            try:
                answers = dns.resolver.resolve(target, "A")
                ips = [str(r) for r in answers]
                if ips:
                    discovered.append({"subdomain": target, "ip": ips[0]})
            except Exception:
                pass
        return discovered
