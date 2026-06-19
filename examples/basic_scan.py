# Basic Scan Example using NetScanner Python API
from scannet import NetScanner

def main():
    print("Initializing NetScanner for localhost (Safe/Private IP)...")
    
    # Needs authorized=True, and scans default top ports
    scanner = NetScanner(
        target="127.0.0.1",
        timeout=1.0,
        threads=10,
        authorized=True
    )
    
    print("Running quick port scan...")
    # Scan ports 22, 80, 135, 443, 3306, 3389
    result = scanner.scan_ports([22, 80, 135, 443, 3306, 3389])
    
    print("\nScan Results Summary:")
    print(f"Target: {result['target']}")
    print(f"Scan Duration: {result['summary']['scan_duration']:.2f} seconds")
    
    hosts = result["hosts"]
    for ip, data in hosts.items():
        print(f"Host: {ip} | Hostname: {data.get('hostname')}")
        ports = data.get("ports", {})
        for port, p_info in ports.items():
            print(f"  - Port {port}: {p_info['state']}")

if __name__ == "__main__":
    main()
