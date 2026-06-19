from dataclasses import dataclass
from enum import Enum

class ScanProfile(Enum):
    QUICK = "quick"
    NORMAL = "normal"
    FULL = "full"
    CUSTOM = "custom"

@dataclass
class ScanConfig:
    timeout: float = 2.0
    threads: int = 10
    rate_limit: int = 0
    allow_public: bool = False
    authorized: bool = False
    profile: ScanProfile = ScanProfile.NORMAL
    
    # Common ports to scan
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 27017]
    
    # Top 100 ports
    TOP_PORTS = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 
        389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 
        1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2049, 2121, 2301, 2525, 2869, 3000, 3128, 
        3268, 3306, 3333, 3389, 4444, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 
        6000, 6001, 6646, 6667, 7000, 8000, 8008, 8080, 8081, 8443, 8888, 9100, 9999, 32768, 49152, 49153, 49154, 49155
    ]

    def apply_profile(self):
        if self.profile == ScanProfile.QUICK:
            self.timeout = 1.0
            self.threads = 30
            self.rate_limit = 100
        elif self.profile == ScanProfile.NORMAL:
            self.timeout = 2.0
            self.threads = 15
            self.rate_limit = 50
        elif self.profile == ScanProfile.FULL:
            self.timeout = 4.0
            self.threads = 5
            self.rate_limit = 10
