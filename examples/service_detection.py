# Service Banner and OS Detection Example
from scannet import NetScanner

def main():
    scanner = NetScanner(
        target="127.0.0.1",
        timeout=2.0,
        authorized=True
    )
    
    print("Running scan with service and OS estimation...")
    # Scan common ports with service + OS detection enabled
    result = scanner.scan_ports([80, 443, 22, 3306], detect_services=True, detect_os=True)
    
    host_info = result["hosts"]["127.0.0.1"]
    print(f"\nEstimated OS: {host_info.get('os_estimation')}")
    
    print("Services:")
    for port, info in host_info.get("ports", {}).items():
        print(f"Port {port}: Service={info.get('service')}, Banner={info.get('banner')}")

if __name__ == "__main__":
    main()
