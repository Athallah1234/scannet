from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from tabulate import tabulate

console = Console()

def format_scan_result(result: Dict[str, Any]) -> str:
    """Pretty prints the scan result block to terminal using rich."""
    if not result:
        return "Empty result"
        
    summary = result.get("summary", {})
    hosts_data = result.get("hosts", {})
    
    console.print("\n[bold cyan]==================================================[/bold cyan]")
    console.print("[bold white]                   NETSCAN REPORT                 [/bold white]")
    console.print("[bold cyan]==================================================[/bold cyan]")
    
    # Print target or scan details
    console.print(f"[bold yellow]Scan Duration:[/bold yellow] {summary.get('scan_duration', 0.0):.2f}s")
    console.print(f"[bold yellow]Total Hosts Discovered:[/bold yellow] {summary.get('active_hosts', 0)}")
    console.print(f"[bold yellow]Total Open Ports:[/bold yellow] {summary.get('open_ports', 0)}")
    console.print("[bold cyan]--------------------------------------------------[/bold cyan]")
    
    for ip, host_info in hosts_data.items():
        console.print(f"\n[bold green]Host: {ip}[/bold green] ({host_info.get('hostname', 'Unknown')})")
        if host_info.get("os_estimation"):
            console.print(f"  [bold]Estimated OS:[/bold] {host_info['os_estimation']}")
            
        ports = host_info.get("ports", {})
        if ports:
            table = Table(title="Open Ports & Services", show_header=True, header_style="bold magenta")
            table.add_column("Port", style="dim", width=12)
            table.add_column("State")
            table.add_column("Service")
            table.add_column("Banner/Details")
            
            for port, info in ports.items():
                table.add_row(
                    str(port), 
                    info.get("state", "unknown"),
                    info.get("service", "unknown"),
                    info.get("banner", "")
                )
            console.print(table)
        else:
            console.print("  [dim]No open ports found.[/dim]")
            
    return ""

def print_pretty_table(headers: List[str], rows: List[List[Any]]) -> None:
    print(tabulate(rows, headers=headers, tablefmt="grid"))
