<div align="center">

<br/>

# 🌐 ScanNet

### _Safe · Educational · Authorized-Only Network Scanning Library for Python_

<br/>

[![PyPI version](https://img.shields.io/pypi/v/ScanNet?color=38bdf8&label=PyPI&logo=pypi&logoColor=white&style=for-the-badge)](https://pypi.org/project/ScanNet/)
[![Python](https://img.shields.io/pypi/pyversions/ScanNet?color=3b82f6&logo=python&logoColor=white&style=for-the-badge)](https://pypi.org/project/ScanNet/)
[![License: MIT](https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/ScanNet?color=8b5cf6&label=Downloads%2FMonth&style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/ScanNet/)
[![Status](https://img.shields.io/pypi/status/ScanNet?style=for-the-badge&color=f59e0b)](https://pypi.org/project/ScanNet/)
[![Code Style](https://img.shields.io/badge/code%20style-clean-22c55e?style=for-the-badge)](https://pypi.org/project/ScanNet/)

<br/>

> **ScanNet** adalah library jaringan Python yang komprehensif, aman, dan bertanggung jawab untuk keperluan **audit jaringan internal**, **monitoring**, dan **pembelajaran keamanan siber**. Dirancang khusus dengan prinsip _authorization-first_ — tidak ada scanning tanpa izin eksplisit.

<br/>

```
╔══════════════════════════════════════════════════════════════╗
║  pip install ScanNet                                         ║
╚══════════════════════════════════════════════════════════════╝
```

</div>

---

## 📋 Daftar Isi

- [✨ Fitur Unggulan](#-fitur-unggulan)
- [⚙️ Instalasi](#️-instalasi)
- [🚀 Quick Start](#-quick-start)
- [🔑 Sistem Otorisasi & Keamanan](#-sistem-otorisasi--keamanan)
- [📚 Panduan Penggunaan API Python](#-panduan-penggunaan-api-python)
  - [NetScanner — Port Scanner Utama](#netscanner--port-scanner-utama)
  - [NetworkDiscovery — Subnet Host Discovery](#networkdiscovery--subnet-host-discovery)
  - [DNSTools — DNS Lookup & Subdomain Check](#dnstools--dns-lookup--subdomain-check)
  - [SubnetTools — Utilitas Subnet CIDR](#subnettools--utilitas-subnet-cidr)
  - [Traceroute — Pelacakan Jalur Jaringan](#traceroute--pelacakan-jalur-jaringan)
- [🖥️ Panduan CLI (Command-Line Interface)](#️-panduan-cli-command-line-interface)
  - [Semua Opsi CLI](#semua-opsi-cli)
  - [Contoh Perintah CLI](#contoh-perintah-cli)
- [📊 Ekspor Laporan](#-ekspor-laporan)
- [🎛️ Profil Scan & Konfigurasi Lanjutan](#️-profil-scan--konfigurasi-lanjutan)
- [🔬 Deteksi Layanan (Service Detection)](#-deteksi-layanan-service-detection)
- [🖥️ Estimasi Sistem Operasi (OS Detection)](#️-estimasi-sistem-operasi-os-detection)
- [🏗️ Arsitektur & Struktur Proyek](#️-arsitektur--struktur-proyek)
- [🧩 Modul & API Referensi Lengkap](#-modul--api-referensi-lengkap)
- [🧪 Testing](#-testing)
- [🔗 Dependencies](#-dependencies)
- [⚠️ Disclaimer & Etika Penggunaan](#️-disclaimer--etika-penggunaan)
- [📄 Lisensi](#-lisensi)
- [🤝 Kontribusi](#-kontribusi)

---

## ✨ Fitur Unggulan

<div align="center">

| 🔍 Fitur | 📝 Deskripsi |
|---|---|
| **Port Scanner Multi-Thread** | Scan ratusan port secara paralel dengan kontrol thread & rate limit |
| **Subnet Host Discovery** | Temukan semua host aktif di subnet menggunakan ICMP, TCP, UDP & ARP |
| **Service Banner Detection** | Identifikasi layanan: HTTP, SSH, FTP, SMTP, DNS, MySQL, PostgreSQL, Redis, MongoDB |
| **OS Fingerprinting** | Estimasi OS target via TTL, port pattern & banner heuristics |
| **DNS Lookup Lengkap** | Query record A, AAAA, MX, NS, TXT, CNAME + reverse lookup + subdomain check |
| **Traceroute Cross-Platform** | Lacak rute paket ke tujuan (Windows & Linux/macOS) |
| **Multi-Format Report Export** | Export ke **JSON**, **CSV**, **HTML** (bergaya), dan **Markdown** |
| **Authorization-First Design** | Wajib konfirmasi otorisasi — tidak ada scanning tanpa izin eksplisit |
| **Rate Limiter Built-in** | Kontrol kecepatan scan untuk menghindari overload jaringan |
| **Scan Profiles** | Preset `quick`, `normal`, dan `full` untuk berbagai kebutuhan |
| **Rich CLI Interface** | Terminal UI yang indah dengan progress bar, spinner, dan tabel berwarna |
| **Public IP Safeguard** | Blokir scan ke IP publik secara default — perlindungan berlapis |

</div>

---

## ⚙️ Instalasi

### Instalasi via PyPI (Direkomendasikan)

```bash
pip install ScanNet
```

### Instalasi dengan versi tertentu

```bash
pip install ScanNet==0.1.0
```

### Instalasi dari Sumber (Development)

```bash
# Clone repository
git clone https://github.com/user/netscan.git
cd netscan

# Install dalam mode editable (development)
pip install -e .

# Atau install dependencies terpisah
pip install -r requirements.txt
```

### Verifikasi Instalasi

```bash
# Cek versi yang terpasang
python -c "import scannet; print(scannet.__version__)"

# Verifikasi CLI tersedia
scannet --help
```

### Persyaratan Sistem

| Komponen | Persyaratan |
|---|---|
| Python | `>= 3.10` |
| OS | Windows, Linux, macOS |
| Privileges | Sebagian fitur (ICMP ping) memerlukan akses administrator/root |

---

## 🚀 Quick Start

### 5 Menit Pertama dengan ScanNet

```python
from scannet import NetScanner

# 1. Inisialisasi scanner dengan target dan konfirmasi otorisasi
scanner = NetScanner(
    target="192.168.1.1",  # IP atau domain target
    timeout=2.0,
    threads=20,
    authorized=True        # ⚠️ WAJIB: konfirmasi Anda punya izin scan
)

# 2. Scan port tertentu
result = scanner.scan_ports([22, 80, 443, 3306, 3389])

# 3. Tampilkan hasil
for ip, host_info in result["hosts"].items():
    print(f"Host: {ip}")
    for port, info in host_info["ports"].items():
        print(f"  Port {port}: {info['state']}")
```

**Output:**
```
Host: 192.168.1.1
  Port 22: open
  Port 80: open
  Port 443: closed
  Port 3306: closed
  Port 3389: closed
```

---

## 🔑 Sistem Otorisasi & Keamanan

ScanNet menerapkan sistem **authorization-first** sebagai perlindungan utama. Setiap operasi scanning **wajib** mendapatkan konfirmasi otorisasi eksplisit.

### Prinsip Keamanan

```
┌─────────────────────────────────────────────────────┐
│  SETIAP SCAN MEMERLUKAN:                            │
│                                                     │
│  ✅ authorized=True    (via Python API)             │
│  ✅ --yes-authorized   (via CLI)                    │
│                                                     │
│  Tanpa konfirmasi ini, scan TIDAK akan berjalan.   │
└─────────────────────────────────────────────────────┘
```

### Perlindungan IP Publik

Secara default, ScanNet **memblokir scanning ke IP publik**. Untuk mengizinkan scan ke IP publik (dengan tanggung jawab penuh):

```python
# Hanya untuk target yang Anda miliki/punya izin eksplisit
scanner = NetScanner(
    target="203.0.113.1",   # IP publik
    authorized=True,
    allow_public=True        # ⚠️ Aktifkan dengan penuh tanggung jawab
)
```

### Pesan Peringatan Etika

Setiap kali scanner dijalankan, ScanNet akan menampilkan peringatan etika:

```
====================== LEGAL & ETHICAL WARNING ======================
WARNING: Only scan systems you own or have explicit written permission to test.
Unauthorized scanning can be illegal, trigger IDS alerts, and disrupt services.
=====================================================================
```

---

## 📚 Panduan Penggunaan API Python

### NetScanner — Port Scanner Utama

`NetScanner` adalah kelas utama untuk melakukan port scanning ke sebuah host.

#### Constructor

```python
from scannet import NetScanner

scanner = NetScanner(
    target="192.168.1.1",    # str: IP address, domain, atau hostname
    timeout=2.0,             # float: waktu tunggu koneksi (detik). Default: 2.0
    threads=20,              # int: jumlah thread paralel. Default: 20
    rate_limit=0,            # int: batas request/detik, 0 = unlimited. Default: 0
    allow_public=False,      # bool: izinkan scan IP publik. Default: False
    authorized=False,        # bool: ⚠️ WAJIB True. Default: False
    profile="normal"         # str: "quick"|"normal"|"full"|"custom". Default: "normal"
)
```

#### `scan_ports()` — Scan Port

```python
result = scanner.scan_ports(
    ports_input=[22, 80, 443],   # List[int] atau str (e.g. "80,443" atau "1-1000")
    scan_type="tcp",             # str: "tcp" (saat ini yang didukung)
    detect_services=False,       # bool: aktifkan service/banner detection
    detect_os=False              # bool: aktifkan OS fingerprinting
)
```

**Struktur Return Value:**

```python
{
    "target": "192.168.1.1",          # Target asli yang diinput
    "resolved_ip": "192.168.1.1",     # IP yang sudah di-resolve
    "hosts": {
        "192.168.1.1": {
            "hostname": "router.local",    # Reverse DNS lookup
            "os_estimation": "Linux/Unix (Estimated, score=5)",  # Jika detect_os=True
            "ports": {
                80: {
                    "state": "open",           # "open" atau "closed"
                    "service": "http",         # Jika detect_services=True
                    "banner": "nginx/1.21.0"   # Jika detect_services=True
                },
                22: {
                    "state": "open",
                    "service": "ssh",
                    "banner": "SSH-2.0-OpenSSH_8.2p1"
                }
            }
        }
    },
    "summary": {
        "scan_duration": 3.24,   # Durasi scan dalam detik
        "active_hosts": 1,       # Jumlah host aktif
        "open_ports": 2          # Jumlah port yang terbuka
    }
}
```

#### `run_full_scan()` — Scan Komprehensif

Menjalankan port scan + service detection + OS fingerprinting sekaligus:

```python
result = scanner.run_full_scan(ports_input=[22, 80, 443, 3306, 3389])
```

#### Contoh Lengkap NetScanner

```python
from scannet import NetScanner
from scannet.utils.exporter import export_report

# Inisialisasi
scanner = NetScanner(
    target="192.168.1.100",
    timeout=3.0,
    threads=30,
    authorized=True,
    profile="full"      # Scan menyeluruh dengan toleransi lebih tinggi
)

# Scan dengan semua fitur aktif
result = scanner.scan_ports(
    ports_input="1-1024",       # Scan port 1 sampai 1024
    detect_services=True,
    detect_os=True
)

# Tampilkan ringkasan
summary = result["summary"]
print(f"Durasi Scan   : {summary['scan_duration']:.2f} detik")
print(f"Port Terbuka  : {summary['open_ports']}")

# Tampilkan detail host
for ip, host in result["hosts"].items():
    print(f"\n[Host] {ip} — {host.get('hostname', 'N/A')}")
    print(f"[OS]   {host.get('os_estimation', 'Tidak terdeteksi')}")
    for port, info in host["ports"].items():
        svc = info.get("service", "unknown")
        banner = info.get("banner", "")
        print(f"  {port:>5}/tcp  {info['state']:<8}  {svc:<12}  {banner}")

# Export laporan
export_report(result, "html", "laporan_scan.html")
print("\nLaporan disimpan ke laporan_scan.html")
```

---

### NetworkDiscovery — Subnet Host Discovery

`NetworkDiscovery` digunakan untuk menemukan semua host aktif dalam satu subnet.

```python
from scannet import NetworkDiscovery

discovery = NetworkDiscovery(
    subnet="192.168.1.0/24",   # str: subnet dalam notasi CIDR
    authorized=True,            # bool: ⚠️ WAJIB True
    allow_public=False,         # bool: izinkan subnet publik
    timeout=2.0,                # float: timeout per host (detik)
    threads=20                  # int: jumlah thread paralel (maks 100)
)

# Jalankan discovery
active_hosts = discovery.discover()

print(f"Host aktif ditemukan: {len(active_hosts)}")
for host in active_hosts:
    print(f"  ✅ {host}")
```

**Metode Discovery yang Digunakan (secara berurutan):**

```
1. ARP Scan (Local)     → Cek ARP table untuk host di jaringan lokal
2. ICMP Ping            → Kirim echo request ke setiap IP
3. TCP Handshake        → Coba koneksi ke port 80, 443, 22, 135, 445
4. UDP Ping             → Probe ke port UDP 137 (NetBIOS) dan 123 (NTP)
```

#### Contoh Scan Subnet Besar

```python
from scannet import NetworkDiscovery

# Scan seluruh subnet /24 (254 host)
discovery = NetworkDiscovery(
    subnet="10.0.0.0/24",
    authorized=True,
    timeout=1.5,
    threads=50  # Thread lebih banyak untuk jaringan besar
)

hosts = discovery.discover()
print(f"\nTotal {len(hosts)} host aktif pada jaringan 10.0.0.0/24:")
for i, h in enumerate(hosts, 1):
    print(f"  {i:>3}. {h}")
```

---

### DNSTools — DNS Lookup & Subdomain Check

```python
from scannet import DNSTools

# 1. Lookup semua record DNS umum
records = DNSTools.lookup("example.com")
# Mengembalikan: {"A": [...], "AAAA": [...], "MX": [...], "NS": [...], "TXT": [...], "CNAME": [...]}

print("=== DNS Records ===")
for rtype, values in records.items():
    if values:
        print(f"  {rtype:6}: {', '.join(values)}")

# 2. Reverse lookup (IP → hostname)
hostname = DNSTools.reverse_lookup("8.8.8.8")
print(f"\nHostname: {hostname}")  # → "dns.google"

# 3. Subdomain discovery (passive check, tanpa brute force agresif)
subs = ["www", "mail", "ftp", "api", "admin", "dev", "staging", "vpn"]
found = DNSTools.check_subdomains("example.com", subs)
print("\n=== Subdomain Aktif ===")
for item in found:
    print(f"  {item['subdomain']} → {item['ip']}")
```

**Record DNS yang Didukung:**

| Record | Deskripsi |
|---|---|
| `A` | IPv4 address dari domain |
| `AAAA` | IPv6 address dari domain |
| `MX` | Mail exchange servers |
| `NS` | Nameservers authoritative |
| `TXT` | Text records (SPF, DKIM, dll) |
| `CNAME` | Canonical name (alias) |

---

### SubnetTools — Utilitas Subnet CIDR

```python
from scannet import SubnetTools

# Dapatkan semua IP host dalam subnet
hosts = SubnetTools.get_hosts("192.168.1.0/24")
print(f"Total host: {len(hosts)}")  # 254

# Informasi subnet
info = SubnetTools.get_subnet_info("192.168.1.0/24")
print(f"Network  : {info['network']}")
print(f"Netmask  : {info['netmask']}")
print(f"Gateway  : {info['gateway']}")
print(f"Broadcast: {info['broadcast']}")
print(f"Hosts    : {info['total_hosts']}")
```

---

### Traceroute — Pelacakan Jalur Jaringan

```python
from scannet import Traceroute

# Lacak rute ke target
hops = Traceroute.trace(
    target="8.8.8.8",
    max_hops=30,
    timeout=2.0
)

print(f"{'Hop':>4}  {'IP Address':<20}  {'RTT'}")
print("-" * 40)
for hop in hops:
    print(f"  {hop['hop']:>2}  {hop['ip']:<20}  {hop['rtt']}")
```

**Output contoh:**
```
 Hop  IP Address            RTT
----------------------------------------
   1  192.168.1.1           1 ms
   2  10.10.1.1             5 ms
   3  203.0.113.1           15 ms
   4  *                     *
   5  8.8.8.8               22 ms
```

> 💡 **Cross-Platform**: Menggunakan `tracert` di Windows dan `traceroute` di Linux/macOS secara otomatis.

---

## 🖥️ Panduan CLI (Command-Line Interface)

ScanNet menyediakan CLI yang kaya fitur dan tampilan terminal yang indah (menggunakan **Rich**).

### Semua Opsi CLI

```
Usage: scannet [OPTIONS]

  NetScan: Safe & Educational Network Auditing and Scan Library CLI.

Options:
  --target TEXT              Target IP atau Domain yang akan di-scan
  --subnet TEXT              Subnet dalam notasi CIDR (misal: 192.168.1.0/24)
  --ports TEXT               Port yang di-scan: '80', '80,443', atau '1-1024'
  --common-ports             Scan port-port umum yang sering digunakan
  --top-ports                Scan top 100 port paling populer
  --discover                 Jalankan host discovery pada subnet
  --service-detect           Deteksi banner dan layanan pada port terbuka
  --os-detect                Lakukan estimasi OS menggunakan heuristik
  --dns                      Lakukan DNS lookup pada domain target
  --traceroute               Lacak rute jaringan ke target
  --export [json|csv|html|markdown|md]
                             Format laporan yang diekspor
  --output TEXT              Path file untuk menyimpan laporan
  --timeout FLOAT            Batas waktu socket (detik). Default: 2.0
  --threads INTEGER          Jumlah thread maksimum. Default: 20
  --rate-limit INTEGER       Batas request per detik (0 = unlimited). Default: 0
  --allow-public             Izinkan scanning IP publik
  --yes-authorized           ⚠️ Konfirmasi eksplisit bahwa Anda punya izin scan
  --debug                    Aktifkan logging debug yang verbose
  --help                     Tampilkan pesan bantuan ini
```

### Contoh Perintah CLI

#### 1. Scan Port Dasar

```bash
# Scan port tertentu pada localhost
scannet --target 127.0.0.1 --ports 22,80,443 --yes-authorized

# Scan range port
scannet --target 192.168.1.1 --ports 1-1024 --yes-authorized

# Scan top 100 port populer
scannet --target 192.168.1.1 --top-ports --yes-authorized

# Scan port-port umum (common ports)
scannet --target 192.168.1.1 --common-ports --yes-authorized
```

#### 2. Host Discovery (Subnet Sweeping)

```bash
# Temukan semua host aktif di subnet
scannet --subnet 192.168.1.0/24 --discover --yes-authorized

# Discovery dengan rate limit dan thread kustom
scannet --subnet 10.0.0.0/24 --discover --threads 50 --rate-limit 100 --yes-authorized
```

#### 3. Deteksi Layanan & OS

```bash
# Scan dengan deteksi service banner
scannet --target 192.168.1.1 --common-ports --service-detect --yes-authorized

# Scan lengkap: port + service + OS estimation
scannet --target 192.168.1.1 --common-ports --service-detect --os-detect --yes-authorized
```

#### 4. DNS Lookup

```bash
# Lookup semua record DNS
scannet --target example.com --dns --yes-authorized

# DNS lookup dengan debug logging
scannet --target google.com --dns --debug --yes-authorized
```

#### 5. Traceroute

```bash
# Lacak rute ke target
scannet --target 8.8.8.8 --traceroute --allow-public --yes-authorized

# Traceroute dengan timeout lebih lama
scannet --target example.com --traceroute --timeout 5.0 --allow-public --yes-authorized
```

#### 6. Ekspor Laporan

```bash
# Export sebagai HTML
scannet --target 192.168.1.1 --common-ports --service-detect \
        --export html --output laporan.html --yes-authorized

# Export sebagai JSON
scannet --target 192.168.1.1 --ports 1-1024 \
        --export json --output hasil_scan.json --yes-authorized

# Export sebagai CSV
scannet --target 192.168.1.1 --top-ports \
        --export csv --output ports.csv --yes-authorized

# Export sebagai Markdown
scannet --target 192.168.1.1 --common-ports \
        --export markdown --output laporan.md --yes-authorized
```

#### 7. Scan Lanjutan — Kombinasi Lengkap

```bash
# Full scan: port + service + OS + export HTML — one command
scannet \
  --target 192.168.1.100 \
  --ports 1-65535 \
  --service-detect \
  --os-detect \
  --export html \
  --output full_report.html \
  --threads 50 \
  --timeout 3.0 \
  --yes-authorized
```

---

## 📊 Ekspor Laporan

ScanNet mendukung 4 format laporan yang dapat diekspor langsung dari Python API maupun CLI.

### Menggunakan Python API

```python
from scannet import NetScanner
from scannet.utils.exporter import export_report
import os

scanner = NetScanner(target="127.0.0.1", authorized=True)
result = scanner.scan_ports([22, 80, 443, 3306])

os.makedirs("reports", exist_ok=True)

# Export ke semua format
formats = {
    "json": "reports/scan.json",
    "csv": "reports/scan.csv",
    "html": "reports/scan.html",
    "markdown": "reports/scan.md"
}

for fmt, path in formats.items():
    success = export_report(result, fmt, path)
    status = "✅" if success else "❌"
    print(f"{status} {fmt.upper():8} → {path}")
```

### Format Laporan

#### 📄 JSON — Structured Data

```json
{
    "target": "192.168.1.1",
    "resolved_ip": "192.168.1.1",
    "hosts": {
        "192.168.1.1": {
            "hostname": "router.local",
            "os_estimation": "Linux/Unix (Estimated, score=5)",
            "ports": {
                "22": { "state": "open", "service": "ssh", "banner": "SSH-2.0-OpenSSH_8.2p1" },
                "80": { "state": "open", "service": "http", "banner": "nginx/1.21.0" }
            }
        }
    },
    "summary": {
        "scan_duration": 3.14,
        "active_hosts": 1,
        "open_ports": 2
    }
}
```

#### 📊 CSV — Spreadsheet Compatible

```
Port,State,Service,Banner
22,open,ssh,SSH-2.0-OpenSSH_8.2p1
80,open,http,nginx/1.21.0
443,closed,,
3306,closed,,
```

#### 🌐 HTML — Laporan Visual Bergaya Dark Theme

Laporan HTML dilengkapi dengan:
- **Dark theme** modern dengan warna biru-hitam elegan
- **Summary cards** dengan statistik scan (durasi, host aktif, port terbuka)
- **Tabel responsif** per host dengan badge berwarna untuk status port (`open` = hijau, `closed` = merah)
- Desain responsive untuk desktop dan mobile

#### 📝 Markdown — Documentation Friendly

```markdown
# NetScan Report

**Target:** 192.168.1.1
**Resolved IP:** 192.168.1.1

## Summary

| Metric | Value |
|--------|-------|
| Scan Duration | 3.14s |
| Active Hosts | 1 |
| Open Ports | 2 |

## Host: 192.168.1.1

| Port | State | Service | Banner |
|------|-------|---------|--------|
| 22 | open | ssh | SSH-2.0-OpenSSH_8.2p1 |
| 80 | open | http | nginx/1.21.0 |
```

---

## 🎛️ Profil Scan & Konfigurasi Lanjutan

ScanNet menyediakan 3 profil scan preset yang menyesuaikan timeout, thread, dan rate limit secara otomatis.

### Scan Profiles

| Profile | Timeout | Threads | Rate Limit | Penggunaan |
|---|---|---|---|---|
| `quick` | 1.0 detik | 30 | 100 req/s | Jaringan lokal cepat, survei awal |
| `normal` | 2.0 detik | 15 | 50 req/s | **Default** — penggunaan umum |
| `full` | 4.0 detik | 5 | 10 req/s | Scan menyeluruh, jaringan lambat |
| `custom` | _manual_ | _manual_ | _manual_ | Konfigurasi penuh oleh pengguna |

### Menggunakan Profile via Python API

```python
from scannet import NetScanner

# Profile Quick — untuk jaringan lokal cepat
scanner_quick = NetScanner(
    target="192.168.1.1",
    authorized=True,
    profile="quick"
)

# Profile Full — untuk hasil paling akurat
scanner_full = NetScanner(
    target="192.168.1.1",
    authorized=True,
    profile="full"
)

# Konfigurasi Custom — kontrol penuh
scanner_custom = NetScanner(
    target="192.168.1.1",
    authorized=True,
    profile="custom",
    timeout=5.0,      # Timeout 5 detik
    threads=8,        # Hanya 8 thread
    rate_limit=20     # Maksimum 20 req/detik
)
```

### Port Preset yang Tersedia

```python
from scannet.utils.config import ScanConfig

# Common Ports (22 port)
print(ScanConfig.COMMON_PORTS)
# [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
#  993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 27017]

# Top 100 Ports
print(len(ScanConfig.TOP_PORTS))  # 100 port paling populer
```

### Parsing Port String

```python
from scannet.utils.helpers import parse_ports

# Berbagai format input yang didukung
ports_1 = parse_ports("80")              # [80]
ports_2 = parse_ports("80,443,8080")    # [80, 443, 8080]
ports_3 = parse_ports("1-1024")         # [1, 2, 3, ..., 1024]
ports_4 = parse_ports("22,80-85,443")   # [22, 80, 81, 82, 83, 84, 85, 443]
```

---

## 🔬 Deteksi Layanan (Service Detection)

ScanNet mampu mengidentifikasi layanan yang berjalan pada port terbuka melalui **banner grabbing** dan **protocol probing** yang aman.

### Layanan yang Didukung

| Port | Layanan | Metode Deteksi |
|---|---|---|
| 80, 8080 | HTTP | HTTP HEAD request, parsing Server header |
| 443, 8443 | HTTPS | TLS handshake + HTTP request |
| 22 | SSH | Banner greeting (SSH-2.0-...) |
| 21 | FTP | Banner greeting (220 ...) |
| 25 | SMTP | Banner greeting (220 ...) |
| 53 | DNS | DNS version query |
| 161 | SNMP | SNMP probe |
| 3306 | MySQL | Protocol greeting packet parsing |
| 5432 | PostgreSQL | SSL request handshake |
| 6379 | Redis | PING/PONG command |
| 27017 | MongoDB | isMaster query |
| 3389 | RDP | Identifier dari port number |
| 445 | SMB | Identifier dari port number |
| _Lainnya_ | Generic | Banner grab + pattern matching |

### Contoh Output Service Detection

```python
from scannet import NetScanner

scanner = NetScanner(target="192.168.1.100", authorized=True)
result = scanner.scan_ports(
    ports_input=[22, 80, 3306, 6379],
    detect_services=True
)

for port, info in result["hosts"]["192.168.1.100"]["ports"].items():
    print(f"Port {port:>5}: {info['state']:<8} | {info.get('service','?'):>12} | {info.get('banner','')}")
```

**Output:**
```
Port    22: open     |          ssh | SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1
Port    80: open     |         http | nginx/1.18.0 (Ubuntu)
Port  3306: open     |        mysql | MySQL 8.0.27
Port  6379: open     |        redis | Redis Key-Value Database
```

---

## 🖥️ Estimasi Sistem Operasi (OS Detection)

ScanNet menggunakan pendekatan **multi-heuristik** untuk mengestimasi OS tanpa memerlukan raw socket atau privilege tinggi.

### Faktor yang Dianalisis

#### 1. TTL (Time-To-Live) Heuristics

| Rentang TTL | OS yang Diestimasi | Skor |
|---|---|---|
| TTL 1–64 | Linux / Unix | +3 |
| TTL 65–128 | Windows | +3 |
| TTL 129–255 | Cisco / Network Device | +3 |

#### 2. Pola Port Terbuka

| Port Terbuka | Indikasi | Skor |
|---|---|---|
| 135, 139, 445, 3389 | Windows | +4 per port |
| 22, 111, 2049 | Linux / Unix | +2 per port |

#### 3. Banner Content Matching

| Kata Kunci dalam Banner | Indikasi | Skor |
|---|---|---|
| `windows`, `iis`, `microsoft` | Windows | +5 |
| `ubuntu`, `debian`, `redhat`, `linux` | Linux / Unix | +5 |
| `cisco`, `router`, `switch` | Network Device | +5 |

### Contoh Penggunaan OS Detection

```python
from scannet import NetScanner

scanner = NetScanner(target="192.168.1.1", authorized=True)
result = scanner.scan_ports(
    ports_input=[22, 80, 135, 443, 3389],
    detect_services=True,
    detect_os=True
)

host = result["hosts"]["192.168.1.1"]
print(f"OS Estimation: {host['os_estimation']}")
# → "Linux/Unix (Estimated, score=7)"
# → "Windows (Estimated, score=11)"
# → "Network Device / Cisco (Estimated, score=8)"
```

> ⚠️ **Catatan**: OS detection ini adalah **estimasi heuristik**, bukan fingerprinting akurat seperti nmap. Hasilnya bersifat indikatif dan dapat memiliki margin error.

---

## 🏗️ Arsitektur & Struktur Proyek

```
scannet/
│
├── scannet/                        # 📦 Package utama
│   ├── __init__.py                 # Entry point & public API exports
│   ├── cli.py                      # 🖥️ CLI interface (Click + Rich)
│   │
│   ├── core/                       # 🔧 Modul inti fungsionalitas
│   │   ├── __init__.py
│   │   ├── scanner.py              # NetScanner — kelas utama
│   │   ├── port_scanner.py         # Implementasi TCP port scanning
│   │   ├── host_discovery.py       # Subnet host discovery (HostDiscovery + NetworkDiscovery)
│   │   ├── service_detector.py     # Service & banner detection
│   │   ├── os_detector.py          # OS fingerprinting heuristics
│   │   ├── dns_tools.py            # DNS lookup (A/AAAA/MX/NS/TXT/CNAME)
│   │   ├── traceroute.py           # Traceroute (cross-platform)
│   │   ├── ping.py                 # ICMP/TCP/UDP/ARP ping utilities
│   │   ├── subnet.py               # SubnetTools — CIDR parsing & host enumeration
│   │   ├── whois_tools.py          # WHOIS lookup
│   │   └── validator.py            # TargetValidator — validasi & otorisasi target
│   │
│   ├── protocols/                  # 🔌 Protocol-specific probers
│   │   ├── http.py                 # HTTP banner grab
│   │   ├── https.py                # HTTPS/TLS probe
│   │   ├── ssh.py                  # SSH banner grab
│   │   ├── ftp.py                  # FTP banner grab
│   │   ├── smtp.py                 # SMTP banner grab
│   │   ├── dns.py                  # DNS version probe
│   │   └── snmp.py                 # SNMP probe
│   │
│   ├── report/                     # 📊 Report generators
│   │   ├── __init__.py
│   │   ├── json_report.py          # Export ke JSON
│   │   ├── csv_report.py           # Export ke CSV
│   │   ├── html_report.py          # Export ke HTML (dark theme, responsive)
│   │   └── markdown_report.py      # Export ke Markdown
│   │
│   └── utils/                      # 🛠️ Utilities & helpers
│       ├── __init__.py
│       ├── config.py               # ScanConfig dataclass + ScanProfile enum
│       ├── exceptions.py           # Custom exceptions
│       ├── exporter.py             # Router ekspor laporan
│       ├── formatter.py            # Rich terminal formatter
│       ├── helpers.py              # parse_ports, validator helpers
│       ├── logger.py               # Logging setup
│       └── rate_limiter.py         # RateLimiter class
│
├── examples/                       # 📖 Contoh penggunaan
│   ├── basic_scan.py               # Port scan sederhana
│   ├── subnet_scan.py              # Subnet host discovery
│   ├── service_detection.py        # Service + OS detection
│   ├── port_scan.py                # Port scan kustom
│   ├── export_report.py            # Export ke semua format
│   └── cli_examples.md             # Contoh perintah CLI
│
├── tests/                          # 🧪 Unit tests
│   ├── test_port_scanner.py
│   ├── test_subnet.py
│   ├── test_validator.py
│   └── test_exporter.py
│
├── setup.py                        # Package configuration
├── requirements.txt                # Dependencies
├── pyproject.toml                  # Build configuration
├── LICENSE                         # MIT License
└── README.md                       # Dokumentasi ini
```

### Diagram Alur Kerja

```
┌─────────────────────────────────────────────────────────┐
│                     User Input                          │
│              (Python API  atau  CLI)                    │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│              TargetValidator                            │
│   • Cek authorized=True / --yes-authorized              │
│   • Tampil ethical warning                              │
│   • Validate format: IP / domain / CIDR                 │
│   • Cek public/private IP (allow_public flag)           │
│   • Resolve domain → IP                                 │
└───────────────────────┬─────────────────────────────────┘
                        │
            ┌───────────┴────────────┐
            │                        │
            ▼                        ▼
  ┌─────────────────┐      ┌──────────────────┐
  │   NetScanner    │      │  HostDiscovery   │
  │                 │      │                  │
  │ • PortScanner   │      │ • ARP Scan       │
  │ • ServiceDetect │      │ • ICMP Ping      │
  │ • OSDetector    │      │ • TCP Handshake  │
  │ • DNSTools      │      │ • UDP Ping       │
  └────────┬────────┘      └────────┬─────────┘
           │                        │
           └───────────┬────────────┘
                       │
                       ▼
          ┌────────────────────────┐
          │    Report & Output     │
          │                        │
          │ • Rich Terminal Print  │
          │ • JSON Export          │
          │ • CSV Export           │
          │ • HTML Export          │
          │ • Markdown Export      │
          └────────────────────────┘
```

---

## 🧩 Modul & API Referensi Lengkap

### `scannet` (Public API)

```python
from scannet import (
    NetScanner,        # Kelas utama untuk port scanning
    NetworkDiscovery,  # Subnet host discovery
    SubnetTools,       # Utilitas CIDR & subnet
    DNSTools,          # DNS lookup & reverse lookup
    Traceroute         # Traceroute path tracking
)

print(scannet.__version__)  # "0.1.0"
```

### `scannet.core`

```python
from scannet.core.scanner import NetScanner
from scannet.core.host_discovery import HostDiscovery, NetworkDiscovery
from scannet.core.port_scanner import PortScanner
from scannet.core.service_detector import ServiceDetector
from scannet.core.os_detector import OSDetector
from scannet.core.dns_tools import DNSTools
from scannet.core.traceroute import Traceroute
from scannet.core.subnet import SubnetTools
from scannet.core.validator import TargetValidator
from scannet.core.ping import PingTools
from scannet.core.whois_tools import WHOISTools
```

### `scannet.utils`

```python
from scannet.utils.config import ScanConfig, ScanProfile
from scannet.utils.exporter import export_report
from scannet.utils.helpers import parse_ports, is_ip_address, is_domain, is_cidr
from scannet.utils.exceptions import NetScanException, TargetValidationError, UnauthorizedScanError
from scannet.utils.formatter import format_scan_result, print_pretty_table
from scannet.utils.logger import setup_logger, get_logger
from scannet.utils.rate_limiter import RateLimiter
```

### `scannet.report`

```python
from scannet.report.json_report import JSONReport
from scannet.report.csv_report import CSVReport
from scannet.report.html_report import HTMLReport
from scannet.report.markdown_report import MarkdownReport

# Semua class memiliki static method:
# ClassName.export(data: Dict[str, Any], filepath: str) -> bool
```

### Custom Exceptions

```python
from scannet.utils.exceptions import (
    NetScanException,         # Base exception
    TargetValidationError,    # Target tidak valid (format salah, IP publik)
    UnauthorizedScanError     # authorized=True tidak diberikan
)

try:
    scanner = NetScanner(target="192.168.1.1", authorized=False)
except UnauthorizedScanError as e:
    print(f"Otorisasi diperlukan: {e}")
except TargetValidationError as e:
    print(f"Target tidak valid: {e}")
except NetScanException as e:
    print(f"Error scan: {e}")
```

---

## 🧪 Testing

### Menjalankan Semua Test

```bash
# Install pytest jika belum ada
pip install pytest

# Jalankan semua test
pytest tests/ -v

# Jalankan dengan coverage report
pip install pytest-cov
pytest tests/ -v --cov=scannet --cov-report=term-missing
```

### Daftar Test yang Tersedia

```
tests/
├── test_port_scanner.py   # Test PortScanner (mock socket)
├── test_subnet.py         # Test SubnetTools (CIDR parsing, host enumeration)
├── test_validator.py      # Test TargetValidator (IP validation, auth check)
└── test_exporter.py       # Test report exporters (JSON, CSV, HTML, Markdown)
```

### Contoh Menjalankan Test Tertentu

```bash
# Test validator saja
pytest tests/test_validator.py -v

# Test exporter dengan output detail
pytest tests/test_exporter.py -v -s

# Test dengan filter nama
pytest tests/ -v -k "test_subnet"
```

---

## 🔗 Dependencies

| Package | Versi Minimum | Fungsi |
|---|---|---|
| [`click`](https://pypi.org/project/click/) | `>= 8.0.0` | CLI framework yang kuat dan fleksibel |
| [`rich`](https://pypi.org/project/rich/) | `>= 12.0.0` | Terminal output yang indah (warna, tabel, progress bar) |
| [`dnspython`](https://pypi.org/project/dnspython/) | `>= 2.2.0` | DNS query untuk lookup A/AAAA/MX/NS/TXT/CNAME |
| [`requests`](https://pypi.org/project/requests/) | `>= 2.27.0` | HTTP/HTTPS service detection |
| [`python-whois`](https://pypi.org/project/python-whois/) | `>= 0.7.3` | WHOIS domain information lookup |
| [`tabulate`](https://pypi.org/project/tabulate/) | `>= 0.8.9` | Pemformatan tabel di terminal |

### Instalasi Manual Dependencies

```bash
pip install click>=8.0.0 rich>=12.0.0 dnspython>=2.2.0 requests>=2.27.0 python-whois>=0.7.3 tabulate>=0.8.9
```

---

## ⚠️ Disclaimer & Etika Penggunaan

> [!CAUTION]
> **PERINGATAN HUKUM & ETIKA — BACA SEBELUM MENGGUNAKAN**

### ✅ Penggunaan yang Diizinkan

- Scan pada **perangkat milik Anda sendiri** (laptop, server, router pribadi)
- Scan pada **jaringan internal organisasi** dengan izin tertulis dari administrator
- Untuk **pembelajaran dan riset keamanan** di lingkungan lab yang terisolasi
- Untuk **audit keamanan resmi** dengan kontrak dan persetujuan pihak yang berwenang
- Penggunaan dalam **CTF (Capture The Flag)** dan tantangan hacking legal
- **Pengujian penetrasi (pentest)** yang dilakukan oleh profesional tersertifikasi

### ❌ Penggunaan yang DILARANG

- Scanning terhadap **IP atau domain yang bukan milik Anda** tanpa izin eksplisit tertulis
- Scanning yang dapat **menggangu layanan atau menyebabkan downtime**
- Penggunaan sebagai alat **reconnaissance untuk serangan siber**
- Scanning pada **infrastruktur pemerintah, militer, atau kritis** tanpa otorisasi resmi
- Semua aktivitas yang melanggar **UU ITE No. 11 Tahun 2008** (Indonesia) atau regulasi sejenis di negara Anda
- Semua aktivitas yang melanggar **Computer Fraud and Abuse Act (CFAA)** (USA), **Computer Misuse Act** (UK), atau undang-undang serupa

### ⚖️ Tanggung Jawab

**Pengembang dan kontributor ScanNet tidak bertanggung jawab** atas penyalahgunaan library ini. Dengan menggunakan ScanNet, Anda menyetujui:

1. Hanya akan menggunakan library ini untuk tujuan yang **legal dan sah**
2. Memiliki **otorisasi eksplisit** sebelum melakukan scanning pada target apapun
3. Memahami dan mematuhi **hukum dan regulasi** yang berlaku di yurisdiksi Anda
4. Bertanggung jawab penuh atas segala konsekuensi dari penggunaan library ini

---

## 📄 Lisensi

Proyek ini dilisensikan di bawah **MIT License**.

```
MIT License

Copyright (c) 2026 NetScan Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

Lihat file [LICENSE](LICENSE) untuk teks lengkap.

---

## 🤝 Kontribusi

Kami menyambut kontribusi dari komunitas! Berikut cara berkontribusi:

### Cara Berkontribusi

1. **Fork** repository ini
2. **Clone** fork Anda: `git clone https://github.com/YOUR_USERNAME/netscan.git`
3. **Buat branch** untuk fitur/bugfix: `git checkout -b feature/nama-fitur-baru`
4. **Buat perubahan** Anda dengan mengikuti coding style yang ada
5. **Tulis atau update test** untuk perubahan Anda
6. **Pastikan semua test lulus**: `pytest tests/ -v`
7. **Commit** perubahan Anda: `git commit -m "feat: tambahkan fitur X"`
8. **Push** ke branch Anda: `git push origin feature/nama-fitur-baru`
9. **Buka Pull Request** dengan deskripsi yang jelas

### Panduan Coding

- Ikuti standar **PEP 8** untuk formatting kode Python
- Tambahkan **type hints** pada semua fungsi dan method baru
- Sertakan **docstring** untuk setiap class dan method publik
- Pastikan semua fitur baru memiliki **test yang memadai**
- Jaga prinsip **authorization-first** — jangan bypass mekanisme otorisasi

### Melaporkan Bug atau Permintaan Fitur

Gunakan [GitHub Issues](https://github.com/user/netscan/issues) untuk:

- 🐛 **Bug Report**: Sertakan langkah reproduksi, output error, dan informasi lingkungan
- 💡 **Feature Request**: Jelaskan kebutuhan dan use case yang ingin dicapai
- 📖 **Documentation**: Saran perbaikan dokumentasi selalu disambut baik

### Konvensi Commit Message

```
feat: tambah fitur baru X
fix: perbaiki bug Y pada modul Z
docs: update dokumentasi untuk fungsi A
test: tambah unit test untuk class B
refactor: refactor implementasi C
perf: optimasi performa D
```

---

<div align="center">

<br/>

**Dibuat dengan ❤️ oleh NetScan Team**

<br/>

[![PyPI](https://img.shields.io/pypi/v/ScanNet?color=38bdf8&label=PyPI&logo=pypi&logoColor=white&style=flat-square)](https://pypi.org/project/ScanNet/)
&nbsp;
[![License](https://img.shields.io/badge/License-MIT-10b981?style=flat-square)](LICENSE)
&nbsp;
[![Python](https://img.shields.io/pypi/pyversions/ScanNet?color=3b82f6&style=flat-square)](https://pypi.org/project/ScanNet/)

<br/>

_Gunakan dengan bijak. Scan hanya yang Anda miliki atau punya izin._ 🛡️

<br/>

</div>
