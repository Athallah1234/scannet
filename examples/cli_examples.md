# NetScan CLI Usage Examples

Ensure that the project is installed using:
```bash
pip install -e .
```

All commands require `--yes-authorized` as a security confirmation indicator.

### 1. Basic Port Range Scan
Scan ports 1 to 1000 on localhost:
```bash
netscan --target 127.0.0.1 --ports 1-1000 --yes-authorized
```

### 2. Network Discovery (Subnet Sweeping)
Discover active hosts on local loopback subnet:
```bash
netscan --subnet 127.0.0.0/30 --discover --yes-authorized
```

### 3. Service and OS Detection Heuristics
Grab service banners and estimate operating system:
```bash
netscan --target 127.0.0.1 --common-ports --service-detect --os-detect --yes-authorized
```

### 4. Path Traceroute
Trace connection hops to target:
```bash
netscan --target 127.0.0.1 --traceroute --yes-authorized
```

### 5. DNS Lookup
Retrieve common DNS records (A, AAAA, MX, CNAME, etc.) for local domain target:
```bash
netscan --target scanme.local --dns --yes-authorized
```

### 6. Export Reports
Export scan results as JSON, HTML, CSV, or Markdown:
```bash
netscan --target 127.0.0.1 --ports 80,22,443 --export html --output report.html --yes-authorized
```
