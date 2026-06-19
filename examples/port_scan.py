# Port range scan example
from scannet import NetScanner

def main():
    # Scan target range
    scanner = NetScanner(
        target="127.0.0.1",
        timeout=1.0,
        threads=20,
        authorized=True
    )
    
    print("Scanning port range 1-1000...")
    result = scanner.scan_ports("1-1000")
    
    ports_found = result["hosts"]["127.0.0.1"]["ports"]
    print(f"Open ports found: {list(ports_found.keys())}")

if __name__ == "__main__":
    main()
