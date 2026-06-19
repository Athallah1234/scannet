import ipaddress
import socket
from rich.console import Console
from scannet.utils.exceptions import TargetValidationError, UnauthorizedScanError
from scannet.utils.helpers import is_ip_address, is_domain, is_cidr

console = Console()

class TargetValidator:
    @staticmethod
    def show_ethics_warning():
        """Prints the mandatory ethical/safety warning to console."""
        console.print(
            "\n[bold red]====================== LEGAL & ETHICAL WARNING ======================[/bold red]"
        )
        console.print(
            "[bold yellow]WARNING: Only scan systems you own or have explicit written permission to test.[/bold yellow]"
        )
        console.print(
            "[bold yellow]Unauthorized scanning can be illegal, trigger IDS alerts, and disrupt services.[/bold yellow]"
        )
        console.print(
            "[bold red]=====================================================================[/bold red]\n"
        )

    @staticmethod
    def validate_target(target: str, allow_public: bool = False, authorized: bool = False) -> str:
        """
        Validates target IP/domain/subnet.
        Blocks public targets by default unless allow_public=True.
        Requires authorized=True to pass.
        Returns resolved IP string.
        """
        if not authorized:
            raise UnauthorizedScanError(
                "Scanning requires explicit authorization confirmation. Pass authorized=True or --yes-authorized."
            )
            
        TargetValidator.show_ethics_warning()

        resolved_ip = ""
        
        if is_ip_address(target):
            resolved_ip = target
        elif is_cidr(target):
            # CIDR notation is allowed for subnet tools but we can check if it is private/public
            net = ipaddress.ip_network(target, strict=False)
            if not allow_public and not net.is_private:
                raise TargetValidationError(
                    f"Target subnet {target} is public. To scan public subnets, enable allow_public=True."
                )
            return target
        elif is_domain(target):
            try:
                resolved_ip = socket.gethostbyname(target)
            except socket.gaierror:
                raise TargetValidationError(f"Could not resolve domain target: {target}")
        else:
            raise TargetValidationError(f"Invalid target format: '{target}'. Must be IP, domain, or CIDR.")

        # Check if IP is private
        ip_obj = ipaddress.ip_address(resolved_ip)
        if not allow_public and not ip_obj.is_private:
            raise TargetValidationError(
                f"Target {target} ({resolved_ip}) is a public destination. To scan public targets, enable allow_public=True."
            )
            
        return resolved_ip
