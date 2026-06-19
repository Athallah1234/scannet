# Network subnet discovery scan example
from scannet import NetworkDiscovery

def main():
    print("Initiating Network Discovery on 127.0.0.0/30 (Local Loopback Subnet)...")
    
    # Authorized confirms scan permission
    discovery = NetworkDiscovery(
        subnet="127.0.0.0/30",
        authorized=True,
        timeout=1.0,
        threads=5
    )
    
    active_hosts = discovery.discover()
    print(f"\nActive hosts on subnet: {active_hosts}")

if __name__ == "__main__":
    main()
