from typing import Dict, Any

class MarkdownReport:
    @staticmethod
    def export(data: Dict[str, Any], filepath: str) -> bool:
        """Saves scan results as structured markdown format."""
        try:
            summary = data.get("summary", {})
            md = []
            md.append("# NetScan Security Scan Report")
            md.append("")
            md.append(f"**Target:** {data.get('target', '')} ({data.get('resolved_ip', '')})")
            md.append(f"**Duration:** {summary.get('scan_duration', 0.0):.2f}s")
            md.append(f"**Active Hosts:** {summary.get('active_hosts', 0)}")
            md.append(f"**Total Open Ports:** {summary.get('open_ports', 0)}")
            md.append("")
            md.append("## Target Summary")
            md.append("")
            
            for ip, host_info in data.get("hosts", {}).items():
                md.append(f"### Host: {ip}")
                md.append(f"- **Hostname:** {host_info.get('hostname', 'Unknown')}")
                md.append(f"- **OS Estimation:** {host_info.get('os_estimation', 'Unknown')}")
                md.append("")
                md.append("| Port | State | Service | Banner / Details |")
                md.append("| --- | --- | --- | --- |")
                
                ports = host_info.get("ports", {})
                for port, info in ports.items():
                    md.append(f"| {port} | {info.get('state', 'unknown')} | {info.get('service', 'unknown')} | {info.get('banner', '')} |")
                if not ports:
                    md.append("| - | - | - | No open ports detected |")
                md.append("")

            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(md))
            return True
        except Exception:
            return False
