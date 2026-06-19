import csv
from typing import Dict, Any

class CSVReport:
    @staticmethod
    def export(data: Dict[str, Any], filepath: str) -> bool:
        """Saves scan details in tabular CSV layout."""
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(["Host IP", "Hostname", "Estimated OS", "Port", "State", "Service", "Banner"])
                
                hosts = data.get("hosts", {})
                for ip, info in hosts.items():
                    hostname = info.get("hostname", "")
                    os_est = info.get("os_estimation", "")
                    ports = info.get("ports", {})
                    
                    if not ports:
                        writer.writerow([ip, hostname, os_est, "None", "None", "None", "None"])
                    else:
                        for port, port_info in ports.items():
                            writer.writerow([
                                ip,
                                hostname,
                                os_est,
                                port,
                                port_info.get("state", ""),
                                port_info.get("service", ""),
                                port_info.get("banner", "")
                            ])
            return True
        except Exception:
            return False
