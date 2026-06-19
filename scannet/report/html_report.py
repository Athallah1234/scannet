from typing import Dict, Any

class HTMLReport:
    @staticmethod
    def export(data: Dict[str, Any], filepath: str) -> bool:
        """Saves scan data into a highly stylized, responsive HTML layout."""
        try:
            summary = data.get("summary", {})
            hosts_html = ""
            
            for ip, host_info in data.get("hosts", {}).items():
                ports_rows = ""
                ports = host_info.get("ports", {})
                for port, info in ports.items():
                    ports_rows += f"""
                    <tr>
                        <td>{port}</td>
                        <td><span class="badge state-{info.get('state', 'unknown')}">{info.get('state', 'unknown')}</span></td>
                        <td>{info.get('service', 'unknown')}</td>
                        <td>{info.get('banner', '')}</td>
                    </tr>
                    """
                
                if not ports_rows:
                    ports_rows = "<tr><td colspan='4' class='text-center'>No open ports detected.</td></tr>"
                    
                hosts_html += f"""
                <div class="card">
                    <div class="card-header">
                        <h3>Host: {ip}</h3>
                        <p>Hostname: {host_info.get('hostname', 'Unknown')} | OS: {host_info.get('os_estimation', 'Unknown')}</p>
                    </div>
                    <div class="card-body">
                        <table>
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>State</th>
                                    <th>Service</th>
                                    <th>Banner/Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {ports_rows}
                            </tbody>
                        </table>
                    </div>
                </div>
                """

            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>NetScan Report</title>
                <style>
                    :root {{
                        --bg-color: #0f172a;
                        --card-bg: #1e293b;
                        --primary: #38bdf8;
                        --text-color: #e2e8f0;
                        --text-muted: #94a3b8;
                        --border-color: #334155;
                        --success: #10b981;
                        --warning: #f59e0b;
                    }}
                    body {{
                        font-family: 'Inter', system-ui, -apple-system, sans-serif;
                        background-color: var(--bg-color);
                        color: var(--text-color);
                        margin: 0;
                        padding: 2rem;
                    }}
                    .container {{
                        max-width: 1000px;
                        margin: 0 auto;
                    }}
                    header {{
                        margin-bottom: 2rem;
                        border-bottom: 1px solid var(--border-color);
                        padding-bottom: 1rem;
                    }}
                    h1 {{
                        color: var(--primary);
                        margin-top: 0;
                    }}
                    .summary-grid {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 1rem;
                        margin-bottom: 2rem;
                    }}
                    .summary-card {{
                        background: var(--card-bg);
                        padding: 1.5rem;
                        border-radius: 8px;
                        border: 1px solid var(--border-color);
                        text-align: center;
                    }}
                    .summary-card h4 {{
                        margin: 0 0 0.5rem 0;
                        color: var(--text-muted);
                        text-transform: uppercase;
                        font-size: 0.8rem;
                        letter-spacing: 0.05em;
                    }}
                    .summary-card p {{
                        margin: 0;
                        font-size: 2rem;
                        font-weight: bold;
                        color: var(--primary);
                    }}
                    .card {{
                        background: var(--card-bg);
                        border-radius: 8px;
                        border: 1px solid var(--border-color);
                        margin-bottom: 1.5rem;
                        overflow: hidden;
                    }}
                    .card-header {{
                        padding: 1.5rem;
                        background: rgba(255, 255, 255, 0.02);
                        border-bottom: 1px solid var(--border-color);
                    }}
                    .card-header h3 {{
                        margin: 0;
                        color: var(--primary);
                    }}
                    .card-header p {{
                        margin: 0.5rem 0 0 0;
                        color: var(--text-muted);
                        font-size: 0.9rem;
                    }}
                    .card-body {{
                        padding: 1.5rem;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                    }}
                    th, td {{
                        padding: 0.75rem 1rem;
                        text-align: left;
                        border-bottom: 1px solid var(--border-color);
                    }}
                    th {{
                        color: var(--text-muted);
                        font-weight: 600;
                    }}
                    .badge {{
                        padding: 0.25rem 0.5rem;
                        border-radius: 4px;
                        font-size: 0.8rem;
                        font-weight: 600;
                    }}
                    .state-open {{
                        background: rgba(16, 185, 129, 0.1);
                        color: var(--success);
                    }}
                    .state-closed {{
                        background: rgba(239, 68, 68, 0.1);
                        color: #ef4444;
                    }}
                    .text-center {{
                        text-align: center;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <header>
                        <h1>NetScan Security Scan Report</h1>
                        <p>Target: {data.get('target', '')} ({data.get('resolved_ip', '')})</p>
                    </header>
                    
                    <div class="summary-grid">
                        <div class="summary-card">
                            <h4>Scan Duration</h4>
                            <p>{summary.get('scan_duration', 0.0):.2f}s</p>
                        </div>
                        <div class="summary-card">
                            <h4>Active Hosts</h4>
                            <p>{summary.get('active_hosts', 0)}</p>
                        </div>
                        <div class="summary-card">
                            <h4>Open Ports</h4>
                            <p>{summary.get('open_ports', 0)}</p>
                        </div>
                    </div>
                    
                    {hosts_html}
                </div>
            </body>
            </html>
            """
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
            return True
        except Exception:
            return False
