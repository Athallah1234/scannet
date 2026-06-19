import re
import ipaddress
from typing import List

def is_ip_address(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False

def is_cidr(val: str) -> bool:
    try:
        ipaddress.ip_network(val, strict=False)
        return True
    except ValueError:
        return False

def is_domain(val: str) -> bool:
    # A simple domain regex
    pattern = re.compile(
        r'^([a-zA-Z0-9]'
        r'([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,6}$'
    )
    return bool(pattern.match(val))

def parse_ports(port_str: str) -> List[int]:
    """
    Parses strings like '80', '80,443', '1-1000' and returns a sorted list of unique port integers.
    """
    ports = set()
    if not port_str:
        return []
        
    parts = port_str.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-')
                start_p, end_p = int(start), int(end)
                if 1 <= start_p <= 65535 and 1 <= end_p <= 65535:
                    ports.update(range(min(start_p, end_p), max(start_p, end_p) + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(list(ports))
