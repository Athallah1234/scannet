import click
import sys
import os
from typing import List
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

# Internal imports
from scannet.core.scanner import NetScanner
from scannet.core.host_discovery import HostDiscovery
from scannet.core.dns_tools import DNSTools
from scannet.core.traceroute import Traceroute
from scannet.utils.config import ScanConfig, ScanProfile
from scannet.utils.logger import setup_logger
from scannet.utils.formatter import format_scan_result, print_pretty_table
from scannet.utils.exporter import export_report
from scannet.utils.helpers import parse_ports
from scannet.utils.exceptions import NetScanException

console = Console()

@click.command()
@click.option("--target", help="Target IP or Domain to scan.")
@click.option("--subnet", help="Subnet range in CIDR notation (e.g. 192.168.1.0/24) for discovery.")
@click.option("--ports", help="Ports to scan, e.g. '80', '80,443', '1-1024'.")
@click.option("--common-ports", is_flag=True, help="Scan common ports.")
@click.option("--top-ports", is_flag=True, help="Scan top 100 ports.")
@click.option("--discover", is_flag=True, help="Run subnet host discovery.")
@click.option("--service-detect", is_flag=True, help="Detect banners and services.")
@click.option("--os-detect", is_flag=True, help="Perform OS detection heuristics.")
@click.option("--dns", is_flag=True, help="Perform domain DNS lookup.")
@click.option("--traceroute", is_flag=True, help="Perform traceroute path tracking.")
@click.option("--export", type=click.Choice(["json", "csv", "html", "markdown", "md"]), help="Export report format.")
@click.option("--output", help="Filepath to save the exported report.")
@click.option("--timeout", type=float, default=2.0, help="Socket timeout limit in seconds.")
@click.option("--threads", type=int, default=20, help="Max thread count for scanning.")
@click.option("--rate-limit", type=int, default=0, help="Rate limit in requests per second.")
@click.option("--allow-public", is_flag=True, help="Allow scanning of public IP ranges.")
@click.option("--yes-authorized", is_flag=True, help="Explicit confirmation of scanning authorization.")
@click.option("--debug", is_flag=True, help="Enable verbose debug logging.")
def cli(
    target, subnet, ports, common_ports, top_ports, discover, service_detect,
    os_detect, dns, traceroute, export, output, timeout, threads, rate_limit,
    allow_public, yes_authorized, debug
):
    """NetScan: Safe & Educational Network Auditing and Scan Library CLI."""
    setup_logger(debug)
    
    if not yes_authorized:
        console.print("[bold red]ERROR: Authorization confirmation required. Use --yes-authorized to confirm you own or have permission to scan the target system.[/bold red]")
        sys.exit(1)

    # Subnet host discovery mode
    if discover:
        if not subnet:
            console.print("[bold red]ERROR: --subnet parameter is required for discovery sweeps.[/bold red]")
            sys.exit(1)
            
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning Subnet...", total=100)
            discovery = HostDiscovery(
                subnet=subnet,
                timeout=timeout,
                threads=threads,
                rate_limit=rate_limit,
                allow_public=allow_public,
                authorized=yes_authorized
            )
            progress.update(task, completed=30)
            active_hosts = discovery.discover()
            progress.update(task, completed=100)
            
        console.print(f"\n[bold green]Active Hosts found: {len(active_hosts)}[/bold green]")
        for h in active_hosts:
            console.print(f" - {h}")
        return

    # DNS Lookup Mode
    if dns:
        if not target:
            console.print("[bold red]ERROR: --target parameter is required for DNS lookups.[/bold red]")
            sys.exit(1)
        console.print(f"\n[bold cyan]Performing DNS queries for {target}...[/bold cyan]")
        dns_res = DNSTools.lookup(target)
        rows = []
        for rtype, records in dns_res.items():
            rows.append([rtype, ", ".join(records) if records else "No records"])
        print_pretty_table(["Record Type", "Results"], rows)
        return

    # Traceroute Mode
    if traceroute:
        if not target:
            console.print("[bold red]ERROR: --target parameter is required for traceroute.[/bold red]")
            sys.exit(1)
        console.print(f"\n[bold cyan]Performing traceroute path tracking to {target}...[/bold cyan]")
        hops = Traceroute.trace(target, timeout=timeout)
        rows = []
        for hop in hops:
            rows.append([hop["hop"], hop["ip"], hop["rtt"]])
        print_pretty_table(["Hop #", "IP Address", "Latency / RTT"], rows)
        return

    # Port scanning mode (Default option when target is given)
    if target:
        # Determine port list
        port_list = []
        if ports:
            port_list = parse_ports(ports)
        elif common_ports:
            port_list = ScanConfig.COMMON_PORTS
        elif top_ports:
            port_list = ScanConfig.TOP_PORTS
        else:
            # Default to top 100 ports if nothing is specified
            port_list = ScanConfig.TOP_PORTS

        try:
            scanner = NetScanner(
                target=target,
                timeout=timeout,
                threads=threads,
                rate_limit=rate_limit,
                allow_public=allow_public,
                authorized=yes_authorized
            )
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Scanning Ports...", total=None)
                scan_result = scanner.scan_ports(
                    ports_input=port_list,
                    detect_services=service_detect,
                    detect_os=os_detect
                )
                progress.update(task, completed=100)
                
            format_scan_result(scan_result)
            
            # Save report
            if export and output:
                success = export_report(scan_result, export, output)
                if success:
                    console.print(f"[bold green]Report successfully written to: {output}[/bold green]")
                else:
                    console.print("[bold red]Failed to export report.[/bold red]")
                    
        except NetScanException as e:
            console.print(f"[bold red]Scan Error: {e}[/bold red]")
            sys.exit(1)
    else:
        console.print("[bold red]ERROR: Either --target or --subnet is required.[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    cli()
