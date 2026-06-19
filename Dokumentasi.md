# 📘 Dokumentasi Teknis ScanNet

> **Versi Dokumen:** 1.0.0 &nbsp;|&nbsp; **Versi Library:** 0.1.0 &nbsp;|&nbsp; **Tanggal:** 19 Juni 2026  
> **Penulis:** NetScan Team &nbsp;|&nbsp; **Lisensi:** MIT

---

## 📋 Daftar Isi

1. [Pendahuluan](#1-pendahuluan)
2. [Filosofi & Desain](#2-filosofi--desain)
3. [Instalasi & Konfigurasi Lingkungan](#3-instalasi--konfigurasi-lingkungan)
4. [Arsitektur Sistem](#4-arsitektur-sistem)
5. [Package `scannet` — Public API](#5-package-scannet--public-api)
6. [Package `scannet.core` — Modul Inti](#6-package-scannetcore--modul-inti)
   - 6.1 [NetScanner](#61-netscanner--scannetcorescannerpy)
   - 6.2 [PortScanner](#62-portscanner--scannetcoreport_scannerpy)
   - 6.3 [HostDiscovery & NetworkDiscovery](#63-hostdiscovery--networkdiscovery--scannetcorehost_discoverypy)
   - 6.4 [ServiceDetector](#64-servicedetector--scannetcoreservice_detectorpy)
   - 6.5 [OSDetector](#65-osdetector--scannetcoreos_detectorpy)
   - 6.6 [DNSTools](#66-dnstools--scannetcoredns_toolspy)
   - 6.7 [Traceroute](#67-traceroute--scannetcoretraceroutepy)
   - 6.8 [SubnetTools](#68-subnettools--scannetcoresubnetpy)
   - 6.9 [PingTools](#69-pingtools--scannetcorepingpy)
   - 6.10 [TargetValidator](#610-targetvalidator--scannetcorevalidatorpy)
   - 6.11 [WHOISTools](#611-whoistools--scannetcorewhois_toolspy)
7. [Package `scannet.protocols` — Protokol Jaringan](#7-package-scannetprotocols--protokol-jaringan)
   - 7.1 [TCP Protocol](#71-tcp-protocol--scannetprotocolstcppy)
   - 7.2 [UDP Protocol](#72-udp-protocol--scannetprotocolsudppy)
   - 7.3 [ICMP Protocol](#73-icmp-protocol--scannetprotocolsicmppy)
   - 7.4 [HTTP Protocol](#74-http-protocol--scannetprotocolshttopy)
   - 7.5 [HTTPS Protocol](#75-https-protocol--scannetprotocolshttpspy)
   - 7.6 [SSH Protocol](#76-ssh-protocol--scannetprotocolssshpy)
   - 7.7 [FTP Protocol](#77-ftp-protocol--scannetprotocolsftppy)
   - 7.8 [SMTP Protocol](#78-smtp-protocol--scannetprotocolssmtppy)
   - 7.9 [DNS Protocol](#79-dns-protocol--scannetprotocolsdnspy)
   - 7.10 [SNMP Protocol](#710-snmp-protocol--scannetprotocolssnmppy)
8. [Package `scannet.utils` — Utilitas](#8-package-scannetutils--utilitas)
   - 8.1 [ScanConfig & ScanProfile](#81-scanconfig--scanprofile--scannetutilsconfigpy)
   - 8.2 [Exceptions](#82-exceptions--scannetutilsexceptionspy)
   - 8.3 [RateLimiter](#83-ratelimiter--scannetutilsrate_limiterpy)
   - 8.4 [Helpers](#84-helpers--scannetutilshelperspy)
   - 8.5 [Logger](#85-logger--scannetutilsloggerpy)
   - 8.6 [Formatter](#86-formatter--scannetutilsformatterpy)
   - 8.7 [Exporter](#87-exporter--scannetutilsexporterpy)
9. [Package `scannet.report` — Generator Laporan](#9-package-scannetreport--generator-laporan)
   - 9.1 [JSONReport](#91-jsonreport--scannetreportjson_reportpy)
   - 9.2 [CSVReport](#92-csvreport--scannetreportcsv_reportpy)
   - 9.3 [HTMLReport](#93-htmlreport--scannetreporthtml_reportpy)
   - 9.4 [MarkdownReport](#94-markdownreport--scannetreportmarkdown_reportpy)
10. [CLI — Command Line Interface](#10-cli--command-line-interface)
11. [Struktur Data — Model Output](#11-struktur-data--model-output)
12. [Alur Kerja & Diagram Interaksi](#12-alur-kerja--diagram-interaksi)
13. [Testing & Verifikasi](#13-testing--verifikasi)
14. [Panduan Pengembang (Contributor Guide)](#14-panduan-pengembang-contributor-guide)
15. [Catatan Keamanan & Etika](#15-catatan-keamanan--etika)
16. [FAQ — Pertanyaan yang Sering Diajukan](#16-faq--pertanyaan-yang-sering-diajukan)
17. [Changelog](#17-changelog)
18. [Referensi & Sumber Daya](#18-referensi--sumber-daya)

---

## 1. Pendahuluan

**ScanNet** adalah library Python open-source yang dirancang untuk melakukan **audit jaringan**, **pemantauan keamanan**, dan **pembelajaran keamanan siber** secara aman, bertanggung jawab, dan dengan prinsip *authorization-first*. Library ini dipublikasikan di PyPI sebagai paket `ScanNet`.

### Tujuan Pengembangan

Library ini dikembangkan dengan tujuan:

- Menyediakan toolkit jaringan **yang mudah digunakan** untuk profesional keamanan, sysadmin, dan pelajar
- Menegakkan **etika dan legalitas** sebagai bagian dari desain, bukan sebatas peringatan
- Memberikan **output yang terstruktur** dan dapat diekspor dalam berbagai format
- Mendukung **lintas platform** (Windows, Linux, macOS) tanpa memerlukan hak akses root untuk sebagian besar fitur

### Kompatibilitas

| Platform | Status | Catatan |
|---|---|---|
| Windows 10/11 | ✅ Penuh | Semua fitur didukung |
| Ubuntu 20.04+ | ✅ Penuh | Semua fitur didukung |
| macOS 12+ | ✅ Penuh | Semua fitur didukung |
| Python 3.10 | ✅ Minimum | Wajib |
| Python 3.11, 3.12 | ✅ Diuji | Kompatibel |

---

## 2. Filosofi & Desain

### 2.1 Prinsip Authorization-First

Setiap operasi yang melibatkan jaringan dalam ScanNet **wajib** melewati lapisan otorisasi. Ini bukan sekadar peringatan — ini diimplementasikan langsung di dalam `TargetValidator` yang dipanggil sebelum *byte pertama* dikirimkan ke jaringan.

```
Input Pengguna
     │
     ▼
TargetValidator.validate_target()
     │
     ├── [authorized == False] ──► UnauthorizedScanError (STOP)
     │
     ├── [format tidak valid] ──► TargetValidationError (STOP)
     │
     ├── [IP publik & allow_public == False] ──► TargetValidationError (STOP)
     │
     └── [VALID] ──► Lanjut ke scanning
```

### 2.2 Desain Modular

Setiap lapisan fungsionalitas dipisahkan secara jelas:

```
Lapisan Antarmuka    →  cli.py (Click + Rich)
Lapisan Orkestrasi   →  core/scanner.py (NetScanner)
Lapisan Eksekusi     →  core/port_scanner.py, core/host_discovery.py
Lapisan Protokol     →  protocols/*.py
Lapisan Utilitas     →  utils/*.py
Lapisan Output       →  report/*.py
```

### 2.3 Thread-Safe by Design

Semua komponen yang berjalan secara paralel menggunakan:
- `concurrent.futures.ThreadPoolExecutor` untuk manajemen thread
- `threading.Lock` di `RateLimiter` untuk keamanan akses bersama
- Pembatasan thread maksimum (`min(threads, 100)`) untuk mencegah overload

### 2.4 Graceful Degradation

ScanNet dirancang untuk *tidak* crash ketika satu operasi gagal:
- Setiap protokol probe membungkus operasinya dalam `try/except`
- Kegagalan service detection pada satu port tidak menghentikan scan port lain
- Traceroute memiliki fallback jika perintah OS tidak tersedia

---

## 3. Instalasi & Konfigurasi Lingkungan

### 3.1 Instalasi via PyPI

```bash
# Instalasi versi terbaru
pip install ScanNet

# Instalasi versi spesifik
pip install ScanNet==0.1.0

# Upgrade ke versi terbaru
pip install --upgrade ScanNet

# Instalasi ke virtual environment (direkomendasikan)
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate.bat       # Windows CMD
venv\Scripts\Activate.ps1       # Windows PowerShell
pip install ScanNet
```

### 3.2 Instalasi dari Sumber

```bash
git clone https://github.com/user/netscan.git
cd netscan

# Mode development (editable install)
pip install -e .

# Hanya install dependencies
pip install -r requirements.txt
```

### 3.3 Verifikasi Instalasi

```bash
# Cek versi via Python
python -c "import scannet; print('ScanNet', scannet.__version__, '— OK')"

# Cek CLI
scannet --help

# Import seluruh public API
python -c "
from scannet import NetScanner, NetworkDiscovery, DNSTools, SubnetTools, Traceroute
print('Semua modul berhasil diimport!')
"
```

### 3.4 Konfigurasi Build System

ScanNet menggunakan build system modern berdasarkan `pyproject.toml`:

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=61.0.0", "wheel"]
build-backend = "setuptools.build_meta"
```

### 3.5 Setup.py — Metadata Paket

```python
# setup.py (ringkasan konfigurasi)
setup(
    name="ScanNet",
    version="0.1.0",
    author="NetScan Team",
    description="A safe, educational, authorized-only network scanning library",
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0.0",
        "rich>=12.0.0",
        "dnspython>=2.2.0",
        "requests>=2.27.0",
        "python-whois>=0.7.3",
        "tabulate>=0.8.9",
    ],
    entry_points={
        "console_scripts": ["scannet=scannet.cli:cli"],
    },
)
```

---

## 4. Arsitektur Sistem

### 4.1 Struktur Direktori Lengkap

```
scannet/                             # Root proyek
│
├── scannet/                         # Package Python utama
│   │
│   ├── __init__.py                  # Public API (versi 0.1.0)
│   │                                # Export: NetScanner, NetworkDiscovery,
│   │                                #         SubnetTools, DNSTools, Traceroute
│   │
│   ├── cli.py                       # CLI entry point (Click + Rich)
│   │                                # Command: scannet [OPTIONS]
│   │
│   ├── core/                        # Modul inti fungsionalitas jaringan
│   │   ├── __init__.py              # Export semua kelas core
│   │   ├── scanner.py               # NetScanner — orkestrasi utama
│   │   ├── port_scanner.py          # PortScanner — TCP/UDP port scan
│   │   ├── host_discovery.py        # HostDiscovery + NetworkDiscovery
│   │   ├── service_detector.py      # ServiceDetector — banner grab
│   │   ├── os_detector.py           # OSDetector — heuristik OS
│   │   ├── dns_tools.py             # DNSTools — A/AAAA/MX/NS/TXT/CNAME
│   │   ├── traceroute.py            # Traceroute — path tracking
│   │   ├── subnet.py                # SubnetTools — CIDR utilities
│   │   ├── ping.py                  # PingTools — ICMP/TCP/UDP/ARP
│   │   ├── validator.py             # TargetValidator — auth & validation
│   │   └── whois_tools.py           # WHOISTools — domain WHOIS
│   │
│   ├── protocols/                   # Implementasi protokol spesifik
│   │   ├── __init__.py
│   │   ├── tcp.py                   # tcp_connect() — TCP connect scan
│   │   ├── udp.py                   # udp_ping() — UDP probe
│   │   ├── icmp.py                  # icmp_ping() — OS ping command
│   │   ├── http.py                  # check_http() — HTTP banner
│   │   ├── https.py                 # check_https() — HTTPS/TLS banner
│   │   ├── ssh.py                   # check_ssh() — SSH banner grab
│   │   ├── ftp.py                   # check_ftp() — FTP banner
│   │   ├── smtp.py                  # check_smtp() — SMTP banner
│   │   ├── dns.py                   # check_dns() — DNS version query
│   │   └── snmp.py                  # check_snmp() — SNMP probe
│   │
│   ├── report/                      # Generator laporan multi-format
│   │   ├── __init__.py              # Export: JSONReport, CSVReport, dll
│   │   ├── json_report.py           # JSONReport.export()
│   │   ├── csv_report.py            # CSVReport.export()
│   │   ├── html_report.py           # HTMLReport.export() — dark theme
│   │   └── markdown_report.py       # MarkdownReport.export()
│   │
│   └── utils/                       # Utilitas & helpers
│       ├── __init__.py              # Export semua utilitas publik
│       ├── config.py                # ScanConfig, ScanProfile
│       ├── exceptions.py            # Custom exception hierarchy
│       ├── rate_limiter.py          # RateLimiter — thread-safe
│       ├── helpers.py               # parse_ports, is_ip_address, dll
│       ├── logger.py                # setup_logger, get_logger (Rich)
│       ├── formatter.py             # format_scan_result, print_pretty_table
│       └── exporter.py              # export_report() — dispatcher
│
├── examples/                        # Contoh penggunaan
│   ├── basic_scan.py
│   ├── subnet_scan.py
│   ├── service_detection.py
│   ├── port_scan.py
│   ├── export_report.py
│   └── cli_examples.md
│
├── tests/                           # Unit tests (unittest)
│   ├── test_port_scanner.py
│   ├── test_subnet.py
│   ├── test_validator.py
│   └── test_exporter.py
│
├── setup.py                         # Package metadata & dependencies
├── pyproject.toml                   # Build system config
├── requirements.txt                 # Dependencies list
├── LICENSE                          # MIT License
├── README.md                        # README ringkas
└── Dokumentasi.md                   # Dokumen ini
```

### 4.2 Diagram Ketergantungan Antar Modul

```
cli.py
  ├── core.scanner (NetScanner)
  │     ├── core.validator (TargetValidator)
  │     ├── core.port_scanner (PortScanner)
  │     │     ├── protocols.tcp (tcp_connect)
  │     │     ├── protocols.udp (udp_ping)
  │     │     └── utils.rate_limiter (RateLimiter)
  │     ├── core.service_detector (ServiceDetector)
  │     │     ├── protocols.http, https, ssh, ftp, smtp, dns, snmp
  │     │     └── [MySQL, PostgreSQL, Redis, MongoDB probes - internal]
  │     ├── core.os_detector (OSDetector)
  │     ├── core.dns_tools (DNSTools)
  │     ├── core.whois_tools (WHOISTools)
  │     ├── core.traceroute (Traceroute)
  │     └── utils.config (ScanConfig, ScanProfile)
  │
  ├── core.host_discovery (HostDiscovery)
  │     ├── core.subnet (SubnetTools)
  │     ├── core.ping (PingTools)
  │     │     ├── protocols.icmp (icmp_ping)
  │     │     ├── protocols.tcp (tcp_connect)
  │     │     └── protocols.udp (udp_ping)
  │     └── utils.rate_limiter (RateLimiter)
  │
  ├── core.dns_tools (DNSTools)
  ├── core.traceroute (Traceroute)
  ├── utils.config (ScanConfig, ScanProfile)
  ├── utils.logger (setup_logger)
  ├── utils.formatter (format_scan_result, print_pretty_table)
  ├── utils.exporter (export_report)
  │     └── report.{json,csv,html,markdown}_report
  ├── utils.helpers (parse_ports)
  └── utils.exceptions (NetScanException)
```

### 4.3 Diagram Alur Eksekusi Scan Port

```
Pengguna → NetScanner(target, ..., authorized=True)
                │
                ▼
        TargetValidator.validate_target()
          ├── Cek authorized flag
          ├── Tampilkan ethics warning
          ├── Deteksi format: IP / CIDR / Domain
          ├── Resolve domain → IP (jika domain)
          └── Cek private/public IP
                │
                ▼
        scanner.scan_ports(ports, detect_services, detect_os)
                │
          ┌─────┴──────────────────────────────────┐
          │                                        │
          ▼                                        ▼
   PortScanner.scan_ports()            [detect_os=True]
   (ThreadPoolExecutor)                OSDetector.get_ttl_for_host()
          │                                        │
          ├── Port 22: tcp_connect() → open        │
          ├── Port 80: tcp_connect() → open        │
          ├── Port 443: tcp_connect() → closed     │
          └── Port N: ...                          │
          │                                        │
          ▼                                        │
   [detect_services=True]                          │
   ServiceDetector.detect_service(port)            │
          │                                        │
          ├── Port 22 → check_ssh() → banner       │
          ├── Port 80 → check_http() → banner      │
          └── Port N → generic_banner_grab()       │
          │                                        │
          └─────────────────┬──────────────────────┘
                            │
                            ▼
                   Build report_data dict
                            │
                            ▼
                   format_scan_result()  (tampil ke terminal)
                            │
                            ▼
                   export_report()  (jika diminta)
```

---

## 5. Package `scannet` — Public API

**File:** `scannet/__init__.py`

Package root yang mengekspos API publik dari library ini.

### Versi

```python
import scannet
print(scannet.__version__)  # "0.1.0"
```

### Ekspor Publik

```python
__all__ = [
    "NetScanner",        # Kelas scanner utama
    "NetworkDiscovery",  # Wrapper subnet discovery
    "SubnetTools",       # Utilitas CIDR
    "DNSTools",          # DNS queries
    "Traceroute"         # Path tracking
]
```

### Import Patterns

```python
# Import semua kelas utama
from scannet import NetScanner, NetworkDiscovery, DNSTools, SubnetTools, Traceroute

# Import spesifik modul inti
from scannet.core import (
    NetScanner, PortScanner, HostDiscovery,
    ServiceDetector, OSDetector, DNSTools,
    Traceroute, SubnetTools, PingTools,
    TargetValidator, WHOISTools
)

# Import utilitas
from scannet.utils import (
    ScanConfig, ScanProfile,
    NetScanException, TargetValidationError,
    UnauthorizedScanError, ScanTimeoutError,
    RateLimiter, parse_ports, export_report,
    setup_logger, get_logger,
    format_scan_result, print_pretty_table
)

# Import report generators
from scannet.report import JSONReport, CSVReport, HTMLReport, MarkdownReport
```

---

## 6. Package `scannet.core` — Modul Inti

### 6.1 NetScanner — `scannet/core/scanner.py`

Kelas utama yang mengorkestrasikan seluruh proses scanning. Menjadi *facade* yang menyatukan `PortScanner`, `ServiceDetector`, `OSDetector`, dan modul-modul lainnya.

#### Kelas: `NetScanner`

```python
class NetScanner:
    def __init__(
        self,
        target: str,
        timeout: float = 2.0,
        threads: int = 20,
        rate_limit: int = 0,
        allow_public: bool = False,
        authorized: bool = False,
        profile: str = "normal"
    )
```

**Parameter Constructor:**

| Parameter | Tipe | Default | Deskripsi |
|---|---|---|---|
| `target` | `str` | — | IP address, domain name, atau hostname target |
| `timeout` | `float` | `2.0` | Timeout koneksi socket dalam detik |
| `threads` | `int` | `20` | Jumlah thread paralel untuk scanning |
| `rate_limit` | `int` | `0` | Request per detik (0 = tidak terbatas) |
| `allow_public` | `bool` | `False` | Izinkan scan IP publik |
| `authorized` | `bool` | `False` | **WAJIB True** — konfirmasi otorisasi |
| `profile` | `str` | `"normal"` | Preset konfigurasi: `"quick"`, `"normal"`, `"full"`, `"custom"` |

**Atribut Instance:**

| Atribut | Tipe | Deskripsi |
|---|---|---|
| `self.target` | `str` | Target asli yang diinput pengguna |
| `self.config` | `ScanConfig` | Objek konfigurasi scan |
| `self.resolved_ip` | `str` | IP hasil resolusi (setelah validasi) |

**Proses Inisialisasi:**
1. Buat `ScanConfig` dengan semua parameter
2. Panggil `config.apply_profile()` untuk terapkan preset
3. Panggil `TargetValidator.validate_target()` — jika gagal, lempar exception

---

#### Method: `scan_ports()`

```python
def scan_ports(
    self,
    ports_input: Union[str, List[int]],
    scan_type: str = "tcp",
    detect_services: bool = False,
    detect_os: bool = False
) -> Dict[str, Any]
```

**Parameter:**

| Parameter | Tipe | Default | Deskripsi |
|---|---|---|---|
| `ports_input` | `str` atau `List[int]` | — | Port yang di-scan. String (`"80"`, `"80,443"`, `"1-1000"`) atau list integer |
| `scan_type` | `str` | `"tcp"` | Tipe scan: `"tcp"` (TCP Connect) |
| `detect_services` | `bool` | `False` | Aktifkan banner grabbing & service detection |
| `detect_os` | `bool` | `False` | Aktifkan OS fingerprinting heuristik |

**Return Value:** `Dict[str, Any]`

```python
{
    "target": str,          # Target input asli
    "resolved_ip": str,     # IP address yang sudah di-resolve
    "hosts": {
        "<ip_address>": {
            "hostname": str,           # Reverse DNS lookup result
            "os_estimation": str,      # OS estimate (jika detect_os=True), else None
            "ports": {
                <port_int>: {
                    "state": "open",           # "open" atau "closed"
                    "service": str,            # Nama layanan (jika detect_services=True)
                    "banner": str              # Banner string (jika detect_services=True)
                }
            }
        }
    },
    "summary": {
        "scan_duration": float,    # Durasi total dalam detik
        "active_hosts": int,       # Selalu 1 untuk scan_ports()
        "open_ports": int          # Jumlah port dengan state "open"
    }
}
```

> **Catatan Penting:** Hanya port dengan state `"open"` atau `"open|filtered"` yang dimasukkan ke dalam dict `ports`. Port yang tertutup tidak dimunculkan di output.

---

#### Method: `run_full_scan()`

```python
def run_full_scan(
    self,
    ports_input: Union[str, List[int]]
) -> Dict[str, Any]
```

Shortcut yang memanggil `scan_ports()` dengan `detect_services=True` dan `detect_os=True`.

**Contoh Penggunaan:**

```python
from scannet import NetScanner

# Inisialisasi
scanner = NetScanner(
    target="192.168.1.1",
    timeout=2.0,
    threads=20,
    authorized=True
)

# ---- Contoh 1: Scan port spesifik ----
result = scanner.scan_ports([22, 80, 443, 8080])

# ---- Contoh 2: Scan dengan string range ----
result = scanner.scan_ports("1-1024")

# ---- Contoh 3: Scan penuh dengan semua fitur ----
result = scanner.run_full_scan([22, 80, 443, 3306, 5432, 6379])

# ---- Contoh 4: Hanya deteksi service, tanpa OS ----
result = scanner.scan_ports(
    ports_input="80,443,8080,8443",
    detect_services=True,
    detect_os=False
)
```

---

### 6.2 PortScanner — `scannet/core/port_scanner.py`

Kelas internal yang melakukan scanning port secara paralel menggunakan `ThreadPoolExecutor`.

#### Kelas: `PortScanner`

```python
class PortScanner:
    def __init__(
        self,
        target: str,
        timeout: float = 2.0,
        threads: int = 20,
        rate_limit: int = 0
    )
```

**Atribut Instance:**

| Atribut | Tipe | Deskripsi |
|---|---|---|
| `self.target` | `str` | IP target |
| `self.timeout` | `float` | Socket timeout |
| `self.threads` | `int` | Thread count (dibatasi `min(threads, 100)`) |
| `self.rate_limiter` | `RateLimiter` | Rate limiter instance |

#### Method: `scan_ports()`

```python
def scan_ports(
    self,
    ports: List[int],
    scan_type: str = "tcp"
) -> Dict[int, Dict[str, Any]]
```

**Logika TCP Scan:**
- Panggil `tcp_connect(host, port, timeout)`
- Jika berhasil connect: state = `"open"`
- Jika `ConnectionRefusedError`, `socket.timeout`, atau `OSError`: state = `"closed"`

**Logika UDP Scan:**
- Panggil `udp_ping(host, port, timeout)`
- Jika timeout atau ada respons: state = `"open|filtered"`
- Jika `ConnectionResetError`: state = `"closed"` (ICMP Unreachable)

**Return Value:**
```python
{
    80: {"state": "open"},
    443: {"state": "open"},
    # Port closed TIDAK dimunculkan
}
```

**Mekanisme Threading:**
```python
with ThreadPoolExecutor(max_workers=self.threads) as executor:
    future_to_port = {executor.submit(scan_single, port): port for port in ports}
    for future in as_completed(future_to_port):
        # Proses hasil setiap port selesai disubmit
```

---

### 6.3 HostDiscovery & NetworkDiscovery — `scannet/core/host_discovery.py`

Dua kelas untuk melakukan discovery host aktif pada subnet.

#### Kelas: `HostDiscovery`

Implementasi utama discovery dengan 4 metode probe yang dijalankan secara sekuensial per host.

```python
class HostDiscovery:
    def __init__(
        self,
        subnet: str,
        timeout: float = 2.0,
        threads: int = 20,
        rate_limit: int = 0,
        allow_public: bool = False,
        authorized: bool = False
    )
```

**Parameter:**

| Parameter | Tipe | Default | Deskripsi |
|---|---|---|---|
| `subnet` | `str` | — | Subnet CIDR (contoh: `"192.168.1.0/24"`) |
| `timeout` | `float` | `2.0` | Timeout per probe |
| `threads` | `int` | `20` | Thread count (maks 100) |
| `rate_limit` | `int` | `0` | Request/detik (0 = unlimited) |
| `allow_public` | `bool` | `False` | Izinkan subnet publik |
| `authorized` | `bool` | `False` | Konfirmasi otorisasi |

#### Method: `discover()`

```python
def discover(self) -> List[str]
```

**Urutan Probe per Host:**

```
Untuk setiap IP dalam subnet:
  1. ARP Scan (PingTools.arp_scan_local)
     └── Parse output `arp -a` (Windows) / `arp -n` (Linux)
     └── Jika IP ditemukan → AKTIF, lanjut ke IP berikutnya

  2. ICMP Ping (PingTools.ping_icmp)
     └── Jalankan `ping -n 1 -w <ms>` (Windows) / `ping -c 1 -W <s>` (Linux)
     └── Jika return code 0 → AKTIF, lanjut ke IP berikutnya

  3. TCP Handshake (PingTools.ping_tcp) pada port:
     └── Port 80 (HTTP)
     └── Port 443 (HTTPS)
     └── Port 22 (SSH)
     └── Port 135 (RPC)
     └── Port 445 (SMB)
     └── Jika salah satu berhasil → AKTIF

  4. UDP Ping (PingTools.ping_udp) pada port:
     └── Port 137 (NetBIOS Name Service)
     └── Port 123 (NTP)
     └── Jika timeout (open|filtered) → AKTIF
```

**Return Value:** `List[str]` — daftar IP host aktif, diurutkan secara ascending.

---

#### Kelas: `NetworkDiscovery`

Wrapper yang menyederhanakan `HostDiscovery` dengan antarmuka yang lebih bersih.

```python
class NetworkDiscovery:
    def __init__(
        self,
        subnet: str,
        authorized: bool = False,
        allow_public: bool = False,
        timeout: float = 2.0,
        threads: int = 20
    )

    def discover(self) -> List[str]
```

**Perbedaan dengan `HostDiscovery`:**
- Urutan parameter berbeda (disesuaikan untuk API publik)
- Secara internal mendelegasikan semua pekerjaan ke `HostDiscovery`

**Contoh:**

```python
from scannet import NetworkDiscovery

discovery = NetworkDiscovery(
    subnet="192.168.0.0/24",
    authorized=True,
    timeout=1.5,
    threads=50
)
active = discovery.discover()
print(f"Ditemukan {len(active)} host aktif:", active)
```

---

### 6.4 ServiceDetector — `scannet/core/service_detector.py`

Mengidentifikasi layanan yang berjalan pada port terbuka melalui banner grabbing dan protocol probing.

#### Kelas: `ServiceDetector`

```python
class ServiceDetector:
    def __init__(self, target: str, timeout: float = 2.0)
```

#### Method: `detect_service(port: int) -> dict`

Mengembalikan `{"service": str, "banner": str}`.

**Routing Service Detection:**

```python
port 80, 8080   → check_http()          → "http"
port 443, 8443  → check_https()         → "https"
port 22         → check_ssh()           → "ssh"
port 21         → check_ftp()           → "ftp"
port 25         → check_smtp()          → "smtp"
port 53         → check_dns()           → "dns"
port 161        → check_snmp()          → "snmp"
port 3306       → _probe_mysql()        → "mysql"
port 5432       → _probe_postgres()     → "postgresql"
port 6379       → _probe_redis()        → "redis"
port 27017      → _probe_mongodb()      → "mongodb"
port 3389       → [identifier]          → "rdp"
port 445        → [identifier]          → "smb"
port lain       → _generic_banner_grab() + _infer_service_from_banner()
```

**Private Methods:**

| Method | Deskripsi |
|---|---|
| `_generic_banner_grab(port)` | Buka koneksi TCP, tunggu banner, fallback kirim `\r\n\r\n` |
| `_infer_service_from_banner(banner)` | Pattern matching: `"ssh"`, `"ftp"`, `"smtp"`, `"http"`, `"amqp"` |
| `_probe_mysql(port)` | Baca greeting packet, cari `"mysql"` dalam data, ekstrak versi |
| `_probe_postgres(port)` | Kirim SSL Request packet `0000000804d2162f`, cek respons `S` atau `N` |
| `_probe_redis(port)` | Kirim `PING\r\n`, cek respons `PONG` atau `NOAUTH` |
| `_probe_mongodb(port)` | Kirim OP_QUERY `isMaster`, cek `"ismaster"` dalam respons |

---

### 6.5 OSDetector — `scannet/core/os_detector.py`

Estimasi OS menggunakan analisis heuristik multi-faktor.

#### Kelas: `OSDetector`

#### Method: `estimate_os(ttl, open_ports, banners) -> str`

```python
@staticmethod
def estimate_os(
    ttl: int,
    open_ports: List[int],
    banners: List[str]
) -> str
```

**Sistem Skor:**

```
Faktor TTL:
  TTL 1–64    → linux_score  += 3  (Linux/Unix default TTL = 64)
  TTL 65–128  → windows_score += 3 (Windows default TTL = 128)
  TTL 129–255 → network_score += 3 (Cisco/Network Device TTL = 255)

Faktor Port:
  Port 135, 139, 445, 3389 → windows_score += 4 (per port)
  Port 22, 111, 2049       → linux_score += 2   (per port)

Faktor Banner:
  "windows", "iis", "microsoft" → windows_score += 5
  "ubuntu", "debian", "redhat", "linux" → linux_score += 5
  "cisco", "router", "switch" → network_score += 5
```

**Output String:**
- `"Windows (Estimated, score=N)"`
- `"Linux/Unix (Estimated, score=N)"`
- `"Network Device / Cisco (Estimated, score=N)"`
- `"Generic OS (Estimated)"` — jika skor sama rata
- `"Unknown OS"` — jika semua input kosong

#### Method: `get_ttl_for_host(host) -> int`

```python
@staticmethod
def get_ttl_for_host(host: str) -> int
```

Menjalankan `ping` via subprocess dan mengekstrak nilai TTL dari output menggunakan regex `r"ttl=(\d+)"`.

**Platform:**
- **Windows:** `ping -n 1 -w 1000 <host>`
- **Linux/macOS:** `ping -c 1 -W 1 <host>`

---

### 6.6 DNSTools — `scannet/core/dns_tools.py`

Toolkit DNS yang memanfaatkan library `dnspython`.

#### Kelas: `DNSTools`

#### Method: `lookup(domain) -> Dict[str, Any]`

```python
@staticmethod
def lookup(domain: str) -> Dict[str, Any]
```

Query record: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`.

**Return:**
```python
{
    "A": ["93.184.216.34"],
    "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
    "MX": ["0 example.com."],
    "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
    "TXT": ["v=spf1 -all"],
    "CNAME": []
}
```

Record yang gagal di-query mengembalikan `[]` (bukan exception).

#### Method: `reverse_lookup(ip_address) -> str`

```python
@staticmethod
def reverse_lookup(ip_address: str) -> str
```

Menggunakan `socket.gethostbyaddr()` untuk PTR record lookup.

#### Method: `check_subdomains(domain, subdomain_list) -> List[Dict[str, str]]`

```python
@staticmethod
def check_subdomains(
    domain: str,
    subdomain_list: List[str]
) -> List[Dict[str, str]]
```

Melakukan query DNS `A` untuk setiap `{sub}.{domain}` dalam daftar.

**Return:**
```python
[
    {"subdomain": "www.example.com", "ip": "93.184.216.34"},
    {"subdomain": "mail.example.com", "ip": "198.51.100.10"}
]
```

---

### 6.7 Traceroute — `scannet/core/traceroute.py`

Pelacakan rute jaringan lintas platform menggunakan perintah OS.

#### Kelas: `Traceroute`

#### Method: `trace(target, max_hops, timeout) -> List[Dict[str, Any]]`

```python
@staticmethod
def trace(
    target: str,
    max_hops: int = 30,
    timeout: float = 2.0
) -> List[Dict[str, Any]]
```

**Implementasi per Platform:**

| Platform | Perintah | Argumen |
|---|---|---|
| Windows | `tracert` | `-d -h <max_hops> -w <timeout_ms> <target>` |
| Linux/macOS | `traceroute` | `-n -m <max_hops> -w <timeout> <target>` |

**Parsing Output:**
- Regex IP: `r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"`
- Regex RTT: `r"(\d+(?:\.\d+)?)\s*ms"`
- Baris dengan `*` → hop unreachable

**Return Value:**
```python
[
    {"hop": 1, "ip": "192.168.1.1", "rtt": "1 ms"},
    {"hop": 2, "ip": "10.10.1.1",   "rtt": "5 ms"},
    {"hop": 3, "ip": "*",            "rtt": "*"},
    {"hop": 4, "ip": "8.8.8.8",     "rtt": "22 ms"}
]
```

**Fallback:** Jika perintah OS tidak tersedia, dikembalikan satu entry dengan error message.

---

### 6.8 SubnetTools — `scannet/core/subnet.py`

Utilitas perhitungan dan operasi subnet CIDR.

#### Kelas: `SubnetTools`

#### Method: `get_subnet_info(cidr) -> Dict[str, Any]`

```python
@staticmethod
def get_subnet_info(cidr: str) -> Dict[str, Any]
```

**Return:**
```python
{
    "cidr": "192.168.1.0/24",
    "network_address": "192.168.1.0",
    "broadcast_address": "192.168.1.255",
    "netmask": "255.255.255.0",
    "total_hosts": 256,
    "usable_hosts": 254,
    "is_private": True,
    "is_loopback": False,
    "is_multicast": False,
    "is_reserved": False
}
```

#### Method: `get_hosts(cidr) -> List[str]`

```python
@staticmethod
def get_hosts(cidr: str) -> List[str]
```

**Batasan keamanan:** Subnet lebih besar dari `/16` diblokir untuk mencegah penggunaan memori berlebihan.

**Contoh nilai:**
```python
SubnetTools.get_hosts("192.168.1.0/30")
# → ["192.168.1.1", "192.168.1.2"]

SubnetTools.get_hosts("10.0.0.0/16")
# ValueError: "Subnets larger than /16 are blocked..."

SubnetTools.get_hosts("192.168.1.100/32")
# → ["192.168.1.100"]
```

#### Method: `check_ip_attributes(ip_str) -> Dict[str, bool]`

```python
@staticmethod
def check_ip_attributes(ip_str: str) -> Dict[str, bool]
```

**Return:**
```python
{
    "is_private": True,
    "is_loopback": False,
    "is_multicast": False,
    "is_reserved": False,
    "is_global": False,
    "is_link_local": False
}
```

---

### 6.9 PingTools — `scannet/core/ping.py`

Facade untuk berbagai metode ping menggunakan implementasi protokol yang sesuai.

#### Kelas: `PingTools`

| Method | Signature | Deskripsi |
|---|---|---|
| `ping_icmp` | `(host, timeout=2.0) -> bool` | ICMP ping via OS command |
| `ping_tcp` | `(host, port=80, timeout=2.0) -> bool` | TCP connect ke port |
| `ping_udp` | `(host, port=123, timeout=2.0) -> bool` | UDP probe ke port |
| `arp_scan_local` | `(host, timeout=2.0) -> bool` | Cek ARP cache lokal |

**Implementasi `arp_scan_local`:**
- **Windows:** `arp -a` — cari IP dalam output
- **Linux/macOS:** `arp -n` — cari IP dalam output

---

### 6.10 TargetValidator — `scannet/core/validator.py`

Komponen keamanan inti yang memvalidasi setiap target sebelum scanning dimulai.

#### Kelas: `TargetValidator`

#### Method: `validate_target(target, allow_public, authorized) -> str`

```python
@staticmethod
def validate_target(
    target: str,
    allow_public: bool = False,
    authorized: bool = False
) -> str
```

**Urutan Validasi:**

```
1. Cek authorized:
   └── False → raise UnauthorizedScanError

2. Tampilkan show_ethics_warning() (selalu)

3. Deteksi tipe target:
   ├── is_ip_address(target):
   │   └── resolved_ip = target
   ├── is_cidr(target):
   │   ├── Cek allow_public jika subnet publik
   │   └── Return target langsung (CIDR dikembalikan apa adanya)
   └── is_domain(target):
       └── resolved_ip = socket.gethostbyname(target)
           └── Gagal → raise TargetValidationError

4. Untuk IP (bukan CIDR):
   └── Jika not allow_public and not ip.is_private:
       └── raise TargetValidationError

5. Return resolved_ip
```

**Exception Hierarchy:**
```
NetScanException (base)
├── TargetValidationError    → Format tidak valid / IP publik ditolak
├── UnauthorizedScanError    → authorized=False
└── ScanTimeoutError         → Timeout scan
```

#### Method: `show_ethics_warning()`

Menampilkan banner peringatan berwarna menggunakan `rich.console`:

```
====================== LEGAL & ETHICAL WARNING ======================
WARNING: Only scan systems you own or have explicit written permission to test.
Unauthorized scanning can be illegal, trigger IDS alerts, and disrupt services.
=====================================================================
```

---

### 6.11 WHOISTools — `scannet/core/whois_tools.py`

Query informasi registrasi domain via WHOIS.

#### Kelas: `WHOISTools`

#### Method: `domain_whois(domain) -> Dict[str, Any]`

```python
@staticmethod
def domain_whois(domain: str) -> Dict[str, Any]
```

**Return:**
```python
{
    "domain_name": "EXAMPLE.COM",
    "registrar": "ICANN",
    "whois_server": "whois.icann.org",
    "referral_url": None,
    "updated_date": "2022-08-14 07:01:31",
    "creation_date": "1995-08-14 04:00:00",
    "expiration_date": "2023-08-13 04:00:00",
    "name_servers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
    "status": ["clientDeleteProhibited", "clientTransferProhibited"],
    "emails": ["hostmaster@iana.org"],
    "country": None
}
```

**Error Handling:** Jika query gagal, dikembalikan `{"error": "WHOIS query failed: <detail>"}`.

---

## 7. Package `scannet.protocols` — Protokol Jaringan

Implementasi level rendah untuk setiap protokol jaringan. Semua fungsi bersifat stateless dan dapat dipanggil langsung.

### 7.1 TCP Protocol — `scannet/protocols/tcp.py`

```python
def tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool
```

**Mekanisme:** TCP 3-way handshake penuh menggunakan `socket.create_connection()`.

```python
# Return True  → SYN → SYN-ACK → ACK → (connected) → RST
# Return False → SYN → RST (ConnectionRefused) / Timeout
```

**Exception yang ditangani:** `socket.timeout`, `ConnectionRefusedError`, `OSError`.

---

### 7.2 UDP Protocol — `scannet/protocols/udp.py`

```python
def udp_ping(host: str, port: int = 123, timeout: float = 2.0) -> bool
```

**Mekanisme:**
1. Kirim paket kosong ke `(host, port)` via `SOCK_DGRAM`
2. Coba baca respons dengan `recvfrom(1024)`

**Interpretasi Hasil:**

| Hasil | State | Arti |
|---|---|---|
| Terima data | `True` | Port merespons (aktif) |
| `socket.timeout` | `True` | Host ada, port mungkin `open\|filtered` |
| `ConnectionResetError` | `False` | ICMP Unreachable diterima → port CLOSED |
| `OSError` | `False` | Error sistem |

---

### 7.3 ICMP Protocol — `scannet/protocols/icmp.py`

```python
def icmp_ping(host: str, timeout: float = 2.0) -> bool
```

**Mekanisme:** Menggunakan perintah `ping` OS (bukan raw socket) untuk menghindari kebutuhan privilege root.

| Platform | Perintah |
|---|---|
| Windows | `ping -n 1 -w <timeout_ms> <host>` |
| Linux/macOS | `ping -c 1 -W <timeout_sec> <host>` |

Return `True` jika exit code = 0.

---

### 7.4 HTTP Protocol — `scannet/protocols/http.py`

```python
def check_http(host: str, port: int = 80, timeout: float = 2.0) -> str
```

**Mekanisme:** `requests.get(f"http://{host}:{port}/", timeout=timeout, verify=False)`

**Return:** `"{Server_Header} (Status: {status_code})"` atau `""` jika gagal.

**Catatan:** SSL warning dinonaktifkan (`InsecureRequestWarning`).

---

### 7.5 HTTPS Protocol — `scannet/protocols/https.py`

```python
def check_https(host: str, port: int = 443, timeout: float = 2.0) -> str
```

Identik dengan `check_http` tetapi menggunakan skema `https://`.

---

### 7.6 SSH Protocol — `scannet/protocols/ssh.py`

```python
def check_ssh(host: str, port: int = 22, timeout: float = 2.0) -> str
```

**Mekanisme:** Buat koneksi TCP, baca banner pertama, verifikasi mengandung `"SSH"`.

**Contoh banner:** `SSH-2.0-OpenSSH_8.4p1 Ubuntu-3ubuntu0.6`

---

### 7.7 FTP Protocol — `scannet/protocols/ftp.py`

```python
def check_ftp(host: str, port: int = 21, timeout: float = 2.0) -> str
```

**Mekanisme:** Baca banner FTP (biasanya dimulai dengan `220`).

**Contoh banner:** `220 ProFTPD 1.3.5e Server (Debian)`

---

### 7.8 SMTP Protocol — `scannet/protocols/smtp.py`

```python
def check_smtp(host: str, port: int = 25, timeout: float = 2.0) -> str
```

**Mekanisme:** Baca greeting SMTP.

**Contoh banner:** `220 mail.example.com ESMTP Postfix`

---

### 7.9 DNS Protocol — `scannet/protocols/dns.py`

```python
def check_dns(host: str, port: int = 53, timeout: float = 2.0) -> str
```

**Mekanisme:** Mengirim DNS version query dan membaca respons.

---

### 7.10 SNMP Protocol — `scannet/protocols/snmp.py`

```python
def check_snmp(host: str, port: int = 161, timeout: float = 2.0) -> str
```

**Mekanisme:** Probe UDP ke port SNMP standard.

---

## 8. Package `scannet.utils` — Utilitas

### 8.1 ScanConfig & ScanProfile — `scannet/utils/config.py`

#### Enum: `ScanProfile`

```python
class ScanProfile(Enum):
    QUICK  = "quick"    # Scan cepat: timeout rendah, thread tinggi
    NORMAL = "normal"   # Default: seimbang
    FULL   = "full"     # Akurat: timeout tinggi, thread rendah
    CUSTOM = "custom"   # Konfigurasi manual penuh
```

#### Dataclass: `ScanConfig`

```python
@dataclass
class ScanConfig:
    timeout: float = 2.0
    threads: int = 10
    rate_limit: int = 0
    allow_public: bool = False
    authorized: bool = False
    profile: ScanProfile = ScanProfile.NORMAL

    # Class-level constants
    COMMON_PORTS: ClassVar[List[int]]  # 22 port umum
    TOP_PORTS: ClassVar[List[int]]     # 100 port populer
```

**`COMMON_PORTS` (22 port):**
```
21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 27017
```

**`TOP_PORTS` (100 port):**
```
7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025..1029, 1110,
1433, 1720, 1723, 1755, 1900, 2000, 2049, 2121, 2301, 2525, 2869, 3000, 3128,
3268, 3306, 3333, 3389, 4444, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357,
5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 6667, 7000, 8000, 8008, 8080,
8081, 8443, 8888, 9100, 9999, 32768, 49152..49155
```

#### Method: `apply_profile()`

Menerapkan preset nilai berdasarkan `self.profile`:

```python
def apply_profile(self):
    if self.profile == ScanProfile.QUICK:
        self.timeout = 1.0
        self.threads = 30
        self.rate_limit = 100
    elif self.profile == ScanProfile.NORMAL:
        self.timeout = 2.0
        self.threads = 15
        self.rate_limit = 50
    elif self.profile == ScanProfile.FULL:
        self.timeout = 4.0
        self.threads = 5
        self.rate_limit = 10
    # CUSTOM → tidak ada perubahan, nilai dari constructor digunakan
```

**Tabel Perbandingan Profile:**

| Profile | Timeout | Threads | Rate Limit | Cocok untuk |
|---|---|---|---|---|
| `quick` | 1.0 detik | 30 | 100/s | LAN cepat, survey awal |
| `normal` | 2.0 detik | 15 | 50/s | Penggunaan umum (default) |
| `full` | 4.0 detik | 5 | 10/s | Jaringan lambat, akurasi tinggi |
| `custom` | _user-defined_ | _user-defined_ | _user-defined_ | Kontrol penuh |

---

### 8.2 Exceptions — `scannet/utils/exceptions.py`

Hierarki exception ScanNet:

```
Exception (Python built-in)
└── NetScanException          # Base exception library
    ├── TargetValidationError     # Target tidak valid
    │   Contoh: IP publik tanpa allow_public, format salah, domain tidak resolve
    ├── UnauthorizedScanError     # authorized=False
    │   Contoh: Scan tanpa konfirmasi otorisasi
    └── ScanTimeoutError          # Timeout (reserved untuk pengembangan)
```

**Penggunaan:**

```python
from scannet.utils.exceptions import (
    NetScanException,
    TargetValidationError,
    UnauthorizedScanError,
    ScanTimeoutError
)

try:
    scanner = NetScanner(target="invalid###", authorized=True)
except UnauthorizedScanError as e:
    print(f"Auth error: {e}")
except TargetValidationError as e:
    print(f"Validation error: {e}")
except NetScanException as e:
    print(f"General error: {e}")
```

---

### 8.3 RateLimiter — `scannet/utils/rate_limiter.py`

Thread-safe rate limiter untuk mengontrol kecepatan scanning.

#### Kelas: `RateLimiter`

```python
class RateLimiter:
    def __init__(self, rate_limit: int = 0)
    def limit(self) -> None
```

**Implementasi:**

```python
self.delay = 1.0 / rate_limit  # Detik per request
self.lock = threading.Lock()   # Thread-safe

def limit(self):
    if self.delay <= 0:  # rate_limit == 0, unlimited
        return
    with self.lock:
        elapsed = time.time() - self.last_time
        sleep_time = self.delay - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)
        self.last_time = time.time()
```

**Contoh Nilai:**

| `rate_limit` | `delay` | Throughput |
|---|---|---|
| `0` | `0.0` (disabled) | Unlimited |
| `10` | `0.1 detik` | 10 req/s |
| `50` | `0.02 detik` | 50 req/s |
| `100` | `0.01 detik` | 100 req/s |

---

### 8.4 Helpers — `scannet/utils/helpers.py`

#### Fungsi: `is_ip_address(val) -> bool`

```python
def is_ip_address(val: str) -> bool
```

Menggunakan `ipaddress.ip_address()` untuk validasi. Mendukung IPv4 dan IPv6.

```python
is_ip_address("192.168.1.1")    # True
is_ip_address("::1")            # True (IPv6)
is_ip_address("256.0.0.1")     # False
is_ip_address("example.com")   # False
```

#### Fungsi: `is_cidr(val) -> bool`

```python
def is_cidr(val: str) -> bool
```

Menggunakan `ipaddress.ip_network(val, strict=False)`.

```python
is_cidr("192.168.1.0/24")  # True
is_cidr("10.0.0.0/8")      # True
is_cidr("192.168.1.1")     # False (tidak ada prefix length)
```

#### Fungsi: `is_domain(val) -> bool`

```python
def is_domain(val: str) -> bool
```

Menggunakan regex: `r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$'`

```python
is_domain("example.com")           # True
is_domain("sub.example.co.id")     # True
is_domain("192.168.1.1")           # False
is_domain("invalid_domain###")     # False
```

#### Fungsi: `parse_ports(port_str) -> List[int]`

```python
def parse_ports(port_str: str) -> List[int]
```

**Format yang didukung:**

| Input | Output |
|---|---|
| `"80"` | `[80]` |
| `"80,443"` | `[80, 443]` |
| `"1-5"` | `[1, 2, 3, 4, 5]` |
| `"22,80-82,443"` | `[22, 80, 81, 82, 443]` |
| `""` | `[]` |

**Aturan validasi:**
- Range port valid: 1–65535
- Port di luar range diabaikan secara diam
- Duplikat dihapus otomatis (menggunakan `set`)
- Hasil selalu **diurutkan ascending**

---

### 8.5 Logger — `scannet/utils/logger.py`

Wrapper logging menggunakan `rich.logging.RichHandler` untuk output terminal berwarna.

#### Fungsi: `setup_logger(debug=False) -> logging.Logger`

```python
def setup_logger(debug: bool = False) -> logging.Logger
```

Mengonfigurasi handler global. Dipanggil satu kali di awal program (biasanya dari CLI).

| `debug=False` | Level `INFO` — tampilkan pesan info, warning, error |
| `debug=True`  | Level `DEBUG` — tampilkan semua pesan termasuk detail internal |

#### Fungsi: `get_logger() -> logging.Logger`

```python
def get_logger() -> logging.Logger
```

Mengembalikan logger yang sudah dikonfigurasi. Jika belum diinisialisasi, panggil `setup_logger()` dengan default.

**Penggunaan dalam kode:**
```python
from scannet.utils.logger import get_logger

logger = get_logger()
logger.info("Port 80: open")
logger.debug("Mencoba koneksi ke 192.168.1.1:22...")
logger.error("Gagal resolve domain: invalid.domain")
```

---

### 8.6 Formatter — `scannet/utils/formatter.py`

Output terminal yang indah menggunakan `rich` dan `tabulate`.

#### Fungsi: `format_scan_result(result) -> str`

```python
def format_scan_result(result: Dict[str, Any]) -> str
```

Mencetak output scan ke terminal dengan format rich:

```
==================================================
                   NETSCAN REPORT
==================================================
Scan Duration: 3.24s
Total Hosts Discovered: 1
Total Open Ports: 2
--------------------------------------------------

Host: 192.168.1.1 (router.local)
  Estimated OS: Linux/Unix (Estimated, score=5)

┏━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port       ┃ State  ┃ Service   ┃ Banner/Details               ┃
┡━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 22         │ open   │ ssh       │ SSH-2.0-OpenSSH_8.4p1       │
│ 80         │ open   │ http      │ nginx/1.18.0 (Status: 200)  │
└────────────┴────────┴───────────┴─────────────────────────────┘
```

#### Fungsi: `print_pretty_table(headers, rows) -> None`

```python
def print_pretty_table(headers: List[str], rows: List[List[Any]]) -> None
```

Menggunakan `tabulate` dengan format `"grid"` untuk tabel sederhana (DNS, Traceroute).

```
+-------------+------------------------------------+
| Record Type | Results                            |
+=============+====================================+
| A           | 93.184.216.34                      |
+-------------+------------------------------------+
| MX          | 0 example.com.                     |
+-------------+------------------------------------+
```

---

### 8.7 Exporter — `scannet/utils/exporter.py`

Dispatcher yang mendelegasikan ekspor ke class report yang sesuai.

#### Fungsi: `export_report(data, format_type, filepath) -> bool`

```python
def export_report(
    data: Dict[str, Any],
    format_type: str,    # "json", "csv", "html", "markdown", "md"
    filepath: str
) -> bool
```

**Routing:**

```python
"json"             → JSONReport.export(data, filepath)
"csv"              → CSVReport.export(data, filepath)
"html"             → HTMLReport.export(data, filepath)
"markdown" / "md"  → MarkdownReport.export(data, filepath)
lainnya            → raise ValueError(f"Unsupported export format: {format_type}")
```

**Return:** `True` jika berhasil, `False` jika terjadi error I/O.

---

## 9. Package `scannet.report` — Generator Laporan

### 9.1 JSONReport — `scannet/report/json_report.py`

```python
class JSONReport:
    @staticmethod
    def export(data: Dict[str, Any], filepath: str) -> bool
```

**Implementasi:** Serialisasi dict hasil scan langsung ke JSON dengan `json.dump()`.

**Contoh output `report.json`:**
```json
{
    "target": "192.168.1.1",
    "resolved_ip": "192.168.1.1",
    "hosts": {
        "192.168.1.1": {
            "hostname": "router.local",
            "os_estimation": "Linux/Unix (Estimated, score=7)",
            "ports": {
                "22": {"state": "open", "service": "ssh", "banner": "SSH-2.0-OpenSSH_8.4p1"},
                "80": {"state": "open", "service": "http", "banner": "nginx/1.18.0 (Status: 200)"}
            }
        }
    },
    "summary": {
        "scan_duration": 3.245,
        "active_hosts": 1,
        "open_ports": 2
    }
}
```

---

### 9.2 CSVReport — `scannet/report/csv_report.py`

```python
class CSVReport:
    @staticmethod
    def export(data: Dict[str, Any], filepath: str) -> bool
```

**Kolom CSV:**

| Host IP | Hostname | Estimated OS | Port | State | Service | Banner |
|---|---|---|---|---|---|---|

**Catatan:** Host tanpa port terbuka ditulis sebagai satu baris dengan nilai `"None"` untuk kolom port.

**Contoh `report.csv`:**
```csv
Host IP,Hostname,Estimated OS,Port,State,Service,Banner
192.168.1.1,router.local,Linux/Unix (Estimated score=7),22,open,ssh,SSH-2.0-OpenSSH_8.4p1
192.168.1.1,router.local,Linux/Unix (Estimated score=7),80,open,http,nginx/1.18.0
```

---

### 9.3 HTMLReport — `scannet/report/html_report.py`

```python
class HTMLReport:
    @staticmethod
    def export(data: Dict[str, Any], filepath: str) -> bool
```

**Fitur HTML Report:**

- **Dark Theme** dengan variabel CSS:
  - Background: `#0f172a` (dark navy)
  - Card: `#1e293b`
  - Accent/Primary: `#38bdf8` (sky blue)
  - Success: `#10b981` (emerald)
  - Warning: `#f59e0b` (amber)
  - Border: `#334155`

- **Layout Responsif:**
  - `max-width: 1000px` container
  - Grid `summary-card` auto-fit

- **Komponen UI:**
  - Header dengan target info
  - Summary cards (Scan Duration, Active Hosts, Open Ports)
  - Per-host card dengan tabel port
  - Badge berwarna: `state-open` (hijau), `state-closed` (merah)

**CSS Variables:**
```css
:root {
    --bg-color: #0f172a;
    --card-bg: #1e293b;
    --primary: #38bdf8;
    --text-color: #e2e8f0;
    --text-muted: #94a3b8;
    --border-color: #334155;
    --success: #10b981;
    --warning: #f59e0b;
}
```

**Encoding:** UTF-8 (`open(filepath, "w", encoding="utf-8")`)

---

### 9.4 MarkdownReport — `scannet/report/markdown_report.py`

```python
class MarkdownReport:
    @staticmethod
    def export(data: Dict[str, Any], filepath: str) -> bool
```

**Format output:**

```markdown
# NetScan Security Scan Report

**Target:** 192.168.1.1 (192.168.1.1)
**Duration:** 3.24s
**Active Hosts:** 1
**Total Open Ports:** 2

## Target Summary

### Host: 192.168.1.1
- **Hostname:** router.local
- **OS Estimation:** Linux/Unix (Estimated, score=7)

| Port | State | Service | Banner / Details |
| --- | --- | --- | --- |
| 22 | open | ssh | SSH-2.0-OpenSSH_8.4p1 |
| 80 | open | http | nginx/1.18.0 (Status: 200) |
```

---

## 10. CLI — Command Line Interface

**File:** `scannet/cli.py`

CLI dibangun menggunakan **Click** (command framework) dan **Rich** (terminal UI).

### Entry Point

```
scannet [OPTIONS]
```

Didaftarkan di `setup.py`:
```python
entry_points={
    "console_scripts": ["scannet=scannet.cli:cli"]
}
```

### Semua Opsi CLI (Referensi Lengkap)

| Opsi | Tipe | Default | Deskripsi |
|---|---|---|---|
| `--target TEXT` | `str` | — | IP atau domain target |
| `--subnet TEXT` | `str` | — | Subnet CIDR untuk host discovery |
| `--ports TEXT` | `str` | — | Port yang di-scan (`"80"`, `"80,443"`, `"1-1024"`) |
| `--common-ports` | flag | `False` | Scan `ScanConfig.COMMON_PORTS` (22 port) |
| `--top-ports` | flag | `False` | Scan `ScanConfig.TOP_PORTS` (100 port) |
| `--discover` | flag | `False` | Aktifkan host discovery mode |
| `--service-detect` | flag | `False` | Aktifkan service/banner detection |
| `--os-detect` | flag | `False` | Aktifkan OS fingerprinting |
| `--dns` | flag | `False` | Lakukan DNS lookup |
| `--traceroute` | flag | `False` | Lakukan traceroute |
| `--export CHOICE` | `json\|csv\|html\|markdown\|md` | — | Format ekspor laporan |
| `--output TEXT` | `str` | — | Path file output laporan |
| `--timeout FLOAT` | `float` | `2.0` | Socket timeout (detik) |
| `--threads INTEGER` | `int` | `20` | Jumlah thread scanning |
| `--rate-limit INTEGER` | `int` | `0` | Request/detik (0 = unlimited) |
| `--allow-public` | flag | `False` | Izinkan scan IP publik |
| `--yes-authorized` | flag | `False` | **WAJIB** — konfirmasi otorisasi |
| `--debug` | flag | `False` | Verbose debug logging |

### Mode Operasi CLI

**Mode 1: Subnet Host Discovery**  
Dipicu oleh `--discover`. Memerlukan `--subnet`.

```bash
scannet --subnet 192.168.1.0/24 --discover --yes-authorized
```

**Alur:**
1. Validasi `--subnet` wajib ada
2. Tampilkan progress bar Rich
3. Inisialisasi `HostDiscovery` dengan parameter
4. Jalankan `discovery.discover()`
5. Tampilkan daftar host aktif

---

**Mode 2: DNS Lookup**  
Dipicu oleh `--dns`. Memerlukan `--target`.

```bash
scannet --target example.com --dns --yes-authorized
```

**Alur:**
1. Validasi `--target` wajib ada
2. Panggil `DNSTools.lookup(target)`
3. Format hasil dalam tabel `print_pretty_table`

---

**Mode 3: Traceroute**  
Dipicu oleh `--traceroute`. Memerlukan `--target`.

```bash
scannet --target 192.168.1.1 --traceroute --yes-authorized
```

**Alur:**
1. Validasi `--target` wajib ada
2. Panggil `Traceroute.trace(target, timeout=timeout)`
3. Format hop dalam tabel

---

**Mode 4: Port Scanning (Default)**  
Dipicu ketika `--target` diberikan tanpa mode lain.

```bash
scannet --target 192.168.1.1 --ports 1-1024 --service-detect --os-detect --yes-authorized
```

**Prioritas Port:**
1. `--ports` (dari string input)
2. `--common-ports` (22 port)
3. `--top-ports` (100 port)
4. Default: `TOP_PORTS` (jika tidak ada pilihan)

**Alur:**
1. Parse port list
2. Inisialisasi `NetScanner` dengan semua parameter
3. Tampilkan spinner Rich selama scan
4. Panggil `scanner.scan_ports()`
5. `format_scan_result()` → tampilkan ke terminal
6. Jika `--export` dan `--output` → `export_report()`

---

### Keamanan CLI

Perintah **wajib** mencantumkan `--yes-authorized`:

```bash
# ❌ GAGAL — tanpa --yes-authorized
scannet --target 192.168.1.1 --ports 80

# Output:
# ERROR: Authorization confirmation required.
# Use --yes-authorized to confirm you own or have permission to scan.

# ✅ BERHASIL
scannet --target 192.168.1.1 --ports 80 --yes-authorized
```

---

## 11. Struktur Data — Model Output

### Model Scan Port (NetScanner)

```
ScanResult = {
    "target": str,                # Input asli pengguna
    "resolved_ip": str,           # IP setelah resolusi DNS
    "hosts": {
        "<ip>": HostResult
    },
    "summary": SummaryResult
}

HostResult = {
    "hostname": str,              # Reverse DNS, atau "" jika gagal
    "os_estimation": str | None,  # None jika detect_os=False
    "ports": {
        <port: int>: PortResult   # Hanya port OPEN yang ada
    }
}

PortResult = {
    "state": "open" | "open|filtered",
    "service": str,               # Hanya ada jika detect_services=True
    "banner": str                 # Hanya ada jika detect_services=True
}

SummaryResult = {
    "scan_duration": float,       # Detik (floating point)
    "active_hosts": int,          # Selalu 1 untuk scan_ports()
    "open_ports": int             # len(scan_results)
}
```

### Model Traceroute

```
TracerouteResult = List[HopResult]

HopResult = {
    "hop": int,       # Nomor hop (mulai dari 1)
    "ip": str,        # IP address atau "*" (unreachable)
    "rtt": str        # Misal "5 ms" atau "*"
}
```

### Model DNS Lookup

```
DNSResult = {
    "A":     List[str],
    "AAAA":  List[str],
    "MX":    List[str],
    "NS":    List[str],
    "TXT":   List[str],
    "CNAME": List[str]
}
```

### Model Subnet Info

```
SubnetInfo = {
    "cidr": str,
    "network_address": str,
    "broadcast_address": str,
    "netmask": str,
    "total_hosts": int,
    "usable_hosts": int,
    "is_private": bool,
    "is_loopback": bool,
    "is_multicast": bool,
    "is_reserved": bool
}
```

### Model Service Detection

```
ServiceResult = {
    "service": str,   # "http", "ssh", "mysql", dll / "unknown"
    "banner": str     # Banner string atau ""
}
```

---

## 12. Alur Kerja & Diagram Interaksi

### Skenario A: Scan Port Lengkap via Python API

```
┌─────────────────────────────────────────────────────────────────┐
│  Pengguna                                                       │
│                                                                 │
│  scanner = NetScanner(target="192.168.1.1", authorized=True)   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  NetScanner.__init__()                                          │
│  ├── Buat ScanConfig(...)                                       │
│  ├── config.apply_profile()  [sesuaikan timeout/thread/rate]   │
│  └── TargetValidator.validate_target("192.168.1.1", ...)       │
│       ├── Cek authorized=True  ✅                               │
│       ├── show_ethics_warning()                                 │
│       ├── is_ip_address("192.168.1.1")  → True                 │
│       ├── ip_address.is_private  → True  ✅                    │
│       └── return "192.168.1.1"  →  self.resolved_ip            │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  scanner.scan_ports([22,80,443], detect_services=True,         │
│                                  detect_os=True)               │
│                                                                 │
│  ├── parse_ports([22,80,443])  → [22, 80, 443]                 │
│  │                                                              │
│  ├── PortScanner("192.168.1.1", timeout=2.0, threads=20)       │
│  │    └── scan_ports([22,80,443], scan_type="tcp")             │
│  │         ├── Thread 1: tcp_connect("...", 22)  → True  OPEN  │
│  │         ├── Thread 2: tcp_connect("...", 80)  → True  OPEN  │
│  │         └── Thread 3: tcp_connect("...", 443) → False CLOSED│
│  │         → results = {22: {"state":"open"}, 80: {"state":"open"}}
│  │                                                              │
│  ├── ServiceDetector("192.168.1.1", timeout=2.0)               │
│  │    ├── detect_service(22) → check_ssh() → "SSH-2.0-..." ✅  │
│  │    └── detect_service(80) → check_http() → "nginx/1.18" ✅  │
│  │                                                              │
│  ├── OSDetector.get_ttl_for_host("192.168.1.1")  → ttl=64      │
│  └── OSDetector.estimate_os(64, [22,80], banners)              │
│       → linux_score=5, windows_score=0                          │
│       → "Linux/Unix (Estimated, score=5)"                       │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
                    Bangun report_data dict
                                │
                                ▼
                    format_scan_result(result)
                    [tampilkan Rich table ke terminal]
                                │
                                ▼
                    export_report(result, "html", "report.html")
                    [HTMLReport.export() → tulis file]
```

---

### Skenario B: Host Discovery via CLI

```
$ scannet --subnet 192.168.1.0/24 --discover --threads 50 --yes-authorized

cli()
 ├── yes_authorized=True → lanjut
 ├── discover=True, subnet="192.168.1.0/24"
 ├── Buat Progress bar Rich
 ├── HostDiscovery("192.168.1.0/24", threads=50, authorized=True)
 │    └── TargetValidator.validate_target("192.168.1.0/24", ...)
 │         ├── is_cidr() → True
 │         └── ip_network.is_private → True  ✅
 │
 └── discovery.discover()
      ├── SubnetTools.get_hosts("192.168.1.0/24")
      │    → ["192.168.1.1", "192.168.1.2", ..., "192.168.1.254"]
      │
      └── ThreadPoolExecutor(max_workers=50)
           ├── Thread 1: check_host("192.168.1.1")
           │    ├── PingTools.arp_scan_local() → True  ✅ AKTIF
           │    └── return "192.168.1.1"
           ├── Thread 2: check_host("192.168.1.2")
           │    ├── arp_scan_local() → False
           │    ├── ping_icmp()      → True  ✅ AKTIF
           │    └── return "192.168.1.2"
           └── Thread N: check_host("192.168.1.N")
                └── ... semua probe → "" (tidak aktif)

Output: Active Hosts found: 2
         - 192.168.1.1
         - 192.168.1.2
```

---

## 13. Testing & Verifikasi

### Menjalankan Test Suite

```bash
# Install pytest
pip install pytest pytest-cov

# Jalankan semua test
pytest tests/ -v

# Dengan coverage report
pytest tests/ -v --cov=scannet --cov-report=term-missing

# Test file tertentu
pytest tests/test_validator.py -v
pytest tests/test_subnet.py -v
pytest tests/test_exporter.py -v
pytest tests/test_port_scanner.py -v

# Test dengan nama tertentu
pytest tests/ -k "test_unauthorized" -v
```

### Deskripsi Test Cases

#### `test_validator.py` — `TestTargetValidator`

| Test Method | Deskripsi | Expected |
|---|---|---|
| `test_unauthorized_scan` | Scan tanpa `authorized=True` | `UnauthorizedScanError` |
| `test_private_target_validation` | IP private `127.0.0.1` dengan auth | Return `"127.0.0.1"` |
| `test_public_target_denied_by_default` | IP publik `8.8.8.8` tanpa `allow_public` | `TargetValidationError` |
| `test_public_target_allowed_explicitly` | IP publik dengan `allow_public=True` | Return `"8.8.8.8"` |
| `test_invalid_target` | Format target tidak valid | `TargetValidationError` |

#### `test_subnet.py` — `TestSubnetTools`

| Test Method | Deskripsi | Expected |
|---|---|---|
| `test_subnet_info_valid` | Info subnet `/24` | Dict dengan `network_address`, `broadcast_address`, dll |
| `test_subnet_hosts` | Host pada `/30` | `["192.168.1.1", "192.168.1.2"]` (2 host) |
| `test_invalid_subnet` | Subnet tidak valid | `ValueError` |

#### `test_port_scanner.py` — `TestPortScanner`

| Test Method | Deskripsi | Expected |
|---|---|---|
| `test_port_scanner_init` | Inisialisasi dengan parameter | Atribut tersimpan benar |
| `test_scan_ports_invalid_host` | Scan TEST-NET-1 (192.0.2.x) | Dict kosong `{}` (timeout) |

#### `test_exporter.py` — `TestExporter`

Menggunakan `tempfile.TemporaryDirectory` untuk file temporary.

| Test Method | Deskripsi | Expected |
|---|---|---|
| `test_export_json` | Export JSON + validasi konten | `success=True`, file ada, data valid |
| `test_export_csv` | Export CSV | `success=True`, file ada |
| `test_export_html` | Export HTML | `success=True`, file ada |
| `test_export_markdown` | Export Markdown | `success=True`, file ada |

### Data Dummy untuk Testing

```python
# Dari test_exporter.py
dummy_data = {
    "target": "127.0.0.1",
    "resolved_ip": "127.0.0.1",
    "hosts": {
        "127.0.0.1": {
            "hostname": "localhost",
            "os_estimation": "Linux/Unix (Estimated, score=3)",
            "ports": {
                80: {
                    "state": "open",
                    "service": "http",
                    "banner": "Apache/2.4.41"
                }
            }
        }
    },
    "summary": {
        "scan_duration": 1.25,
        "active_hosts": 1,
        "open_ports": 1
    }
}
```

---

## 14. Panduan Pengembang (Contributor Guide)

### 14.1 Menyiapkan Lingkungan Development

```bash
# Clone dan setup
git clone https://github.com/user/netscan.git
cd netscan

# Virtual environment
python -m venv venv
source venv/bin/activate     # Linux/macOS
venv\Scripts\Activate.ps1   # Windows PowerShell

# Editable install
pip install -e .

# Install dev dependencies
pip install pytest pytest-cov black isort mypy
```

### 14.2 Standar Kode

**Formatting:** PEP 8 + Black formatter

```bash
black scannet/ tests/         # Auto-format kode
isort scannet/ tests/         # Sort imports
mypy scannet/                  # Type checking
```

**Type Hints:** Semua fungsi publik WAJIB memiliki type hints

```python
# ✅ Benar
def scan_ports(
    self,
    ports_input: Union[str, List[int]],
    scan_type: str = "tcp",
    detect_services: bool = False
) -> Dict[str, Any]:

# ❌ Salah
def scan_ports(self, ports_input, scan_type="tcp"):
```

**Docstrings:** Google style untuk semua class dan method publik

```python
def detect_service(self, port: int) -> dict:
    """Attempts to securely identify service running on specified port.

    Args:
        port: TCP port number to probe (1-65535).

    Returns:
        Dict with keys 'service' (str) and 'banner' (str).
        Returns {"service": "unknown", "banner": ""} if detection fails.
    """
```

### 14.3 Konvensi Commit

```
<type>(<scope>): <description>

feat(core): tambah dukungan IPv6 di TargetValidator
fix(protocols): perbaiki timeout handling di tcp_connect
docs(api): update docstring NetScanner.scan_ports
test(validator): tambah test case untuk CIDR publik
refactor(utils): ekstrak port validation ke helper terpisah
perf(scanner): optimasi ThreadPoolExecutor untuk scan besar
style(cli): format ulang opsi CLI dengan Click decorators
chore(deps): update dnspython ke versi 2.4.0
```

### 14.4 Menambahkan Protokol Baru

1. **Buat file baru** di `scannet/protocols/`:

```python
# scannet/protocols/redis_cluster.py
import socket

def check_redis_cluster(host: str, port: int = 7000, timeout: float = 2.0) -> str:
    """Check if port serves Redis Cluster node."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"CLUSTER INFO\r\n")
            data = sock.recv(256).decode('utf-8', errors='ignore')
            if "cluster_enabled" in data:
                return "Redis Cluster Node"
    except Exception:
        pass
    return ""
```

2. **Daftarkan di `ServiceDetector`** (`scannet/core/service_detector.py`):

```python
from scannet.protocols.redis_cluster import check_redis_cluster

# Dalam detect_service():
elif port == 7000:
    banner = check_redis_cluster(self.target, port, self.timeout)
    if banner:
        service = "redis-cluster"
```

3. **Tulis unit test** di `tests/test_service_detector.py`

### 14.5 Menambahkan Format Laporan Baru

1. **Buat class report** di `scannet/report/`:

```python
# scannet/report/xml_report.py
import xml.etree.ElementTree as ET
from typing import Dict, Any

class XMLReport:
    @staticmethod
    def export(data: Dict[str, Any], filepath: str) -> bool:
        """Export scan results as XML."""
        try:
            root = ET.Element("ScanReport")
            # ... build XML tree
            tree = ET.ElementTree(root)
            tree.write(filepath, encoding="utf-8", xml_declaration=True)
            return True
        except Exception:
            return False
```

2. **Daftarkan di `exporter.py`**:

```python
elif format_type == "xml":
    from scannet.report.xml_report import XMLReport
    return XMLReport.export(data, filepath)
```

3. **Tambahkan ke CLI `--export`** di `cli.py`:

```python
@click.option("--export", type=click.Choice(["json", "csv", "html", "markdown", "md", "xml"]), ...)
```

### 14.6 Panduan Pull Request

Sebelum submit PR, pastikan:

```bash
# 1. Semua test lulus
pytest tests/ -v

# 2. Coverage tidak turun
pytest tests/ --cov=scannet --cov-report=term-missing

# 3. Kode diformat
black scannet/ tests/
isort scannet/ tests/

# 4. Type checking bersih
mypy scannet/ --ignore-missing-imports

# 5. Tidak ada breaking change pada public API
# Cek scannet/__init__.py dan scannet/core/__init__.py
```

---

## 15. Catatan Keamanan & Etika

### 15.1 Desain Pertahanan Berlapis

ScanNet mengimplementasikan **defense-in-depth** untuk mencegah penyalahgunaan:

```
Lapisan 1: Flag Otorisasi
  → authorized=True / --yes-authorized WAJIB ada
  → Tanpa flag ini, library TIDAK melakukan request jaringan apapun

Lapisan 2: Validasi Target
  → IP publik DIBLOKIR secara default
  → allow_public=True HARUS eksplisit diaktifkan
  → Format target tidak valid → exception sebelum scanning

Lapisan 3: Peringatan Etika
  → Ditampilkan SETIAP KALI scan dijalankan (tidak bisa dinonaktifkan)
  → Mengingatkan pengguna tentang konsekuensi hukum

Lapisan 4: Rate Limiting
  → Mencegah flooding jaringan target
  → Default profil "normal": 50 req/s

Lapisan 5: Thread Limiting
  → Maksimum 100 thread (min(threads, 100))
  → Mencegah resource exhaustion di mesin lokal

Lapisan 6: No Exploitation
  → ServiceDetector HANYA membaca banner, tidak exploit
  → Tidak ada password brute-force
  → Tidak ada payload injeksi
```

### 15.2 Perilaku yang Dipantau dan Dicegah

| Skenario | Pencegahan |
|---|---|
| Scan IP publik tanpa izin | `allow_public=False` (default) + `TargetValidationError` |
| Scan tanpa konfirmasi | `authorized=False` (default) + `UnauthorizedScanError` |
| Flooding target | `RateLimiter` + profil scan |
| Memory exhaustion pada subnet besar | Blokir subnet > `/16` |
| Thread overload | `min(threads, 100)` |
| Eksploitasi aktif | Tidak ada payload eksploit dalam kode |

### 15.3 Kasus Penggunaan yang Diizinkan

```
✅ DIIZINKAN:
  • Audit keamanan jaringan internal organisasi sendiri
  • Pemantauan infrastruktur yang dimiliki sendiri
  • Pembelajaran dan penelitian di lab terisolasi
  • CTF (Capture The Flag) dan lingkungan hacking legal
  • Penetration testing dengan kontrak tertulis

❌ DILARANG:
  • Scan host yang bukan milik sendiri
  • Reconnaissance untuk serangan
  • Gangguan layanan (DoS-like behavior)
  • Scan infrastruktur kritis tanpa izin
  • Melanggar hukum setempat
```

### 15.4 Regulasi yang Relevan

| Wilayah | Regulasi | Pasal Relevan |
|---|---|---|
| Indonesia | UU ITE No. 11/2008 jo. No. 19/2016 | Pasal 30, 31, 32 |
| USA | Computer Fraud and Abuse Act (CFAA) | 18 U.S.C. § 1030 |
| UK | Computer Misuse Act 1990 | Section 1-3 |
| Eropa | NIS2 Directive | Article 21 |
| Australia | Criminal Code Act 1995 | Division 477-478 |

---

## 16. FAQ — Pertanyaan yang Sering Diajukan

**Q: Mengapa saya harus menggunakan `authorized=True`? Apakah bisa dihapus?**  
A: `authorized=True` adalah persyaratan wajib yang tidak bisa dilewati. Ini adalah perlindungan hukum untuk library dan pengguna. Tanpanya, `UnauthorizedScanError` akan selalu dilempar sebelum koneksi jaringan apapun terjadi.

---

**Q: Apakah ScanNet bisa scan IP publik seperti situs web?**  
A: Bisa, tetapi memerlukan `allow_public=True` secara eksplisit. Anda bertanggung jawab penuh untuk memastikan Anda memiliki izin legal untuk scan target tersebut.

---

**Q: Mengapa hanya port `"open"` yang muncul di hasil scan?**  
A: `PortScanner` hanya menyimpan port dengan state `"open"` atau `"open|filtered"` ke dalam hasil. Port `"closed"` tidak disertakan untuk menjaga output tetap bersih dan relevan.

---

**Q: Apa perbedaan `HostDiscovery` dan `NetworkDiscovery`?**  
A: Secara fungsional identik. `HostDiscovery` adalah implementasi utama. `NetworkDiscovery` adalah wrapper yang menyederhanakan urutan parameter untuk API publik yang lebih bersih.

---

**Q: Mengapa `SubnetTools.get_hosts()` memblokir subnet > `/16`?**  
A: Subnet `/16` saja sudah mengandung 65.536 host. Untuk `/8` ada 16 juta lebih. Ini akan menyebabkan penggunaan memori yang sangat besar. Batasan ini melindungi mesin pengguna dari OOM (Out of Memory).

---

**Q: Apakah ScanNet memerlukan hak akses root/administrator?**  
A: Sebagian besar fitur **tidak** memerlukan root. ScanNet sengaja menggunakan `subprocess.ping` (bukan raw ICMP socket) dan `TCP Connect` (bukan SYN scan) untuk menghindari kebutuhan privilege. Hanya fitur ARP scanning di beberapa sistem Linux mungkin memerlukan elevated privilege.

---

**Q: Bagaimana cara menambahkan timeout yang lebih tinggi untuk jaringan lambat?**  
A: Gunakan `profile="full"` (timeout 4 detik) atau set manual: `NetScanner(target=..., timeout=8.0, threads=3, rate_limit=5, authorized=True)`

---

**Q: Apakah ScanNet bisa melakukan SYN scan (half-open scan) seperti nmap?**  
A: Tidak. ScanNet menggunakan **TCP Connect scan** (full 3-way handshake) yang tidak memerlukan raw socket. SYN scan memerlukan raw socket dan privilege root, serta memiliki implikasi legal yang lebih besar.

---

**Q: Bagaimana cara menonaktifkan pesan ethics warning?**  
A: Tidak bisa dan tidak seharusnya dinonaktifkan. Pesan ini adalah bagian fundamental dari desain library.

---

**Q: Apakah ScanNet mendukung IPv6?**  
A: Parsing IP menggunakan `ipaddress.ip_address()` yang mendukung IPv6, dan `is_ip_address("::1")` akan mengembalikan `True`. Namun, dukungan end-to-end IPv6 untuk scanning belum sepenuhnya diuji.

---

**Q: Bagaimana cara mengintegrasikan ScanNet dengan sistem monitoring?**  
A: Gunakan Python API dan ekspor ke JSON, lalu proses hasilnya sesuai kebutuhan. Contoh integrasi sederhana:

```python
import json
from scannet import NetScanner
from scannet.utils.exporter import export_report

def run_scheduled_scan(target: str, ports: list) -> dict:
    scanner = NetScanner(target=target, authorized=True)
    result = scanner.scan_ports(ports)
    export_report(result, "json", f"/var/log/scans/{target}.json")
    return result

# Integrasi dengan sistem alerting
result = run_scheduled_scan("192.168.1.1", [22, 80, 443, 3306])
open_ports = result["summary"]["open_ports"]
if open_ports > 5:
    send_alert(f"Host {result['target']} memiliki {open_ports} port terbuka!")
```

---

## 17. Changelog

### v0.1.0 (19 Juni 2026) — Rilis Pertama

**Fitur Baru:**
- `NetScanner` — port scanning TCP/UDP multi-thread
- `NetworkDiscovery` / `HostDiscovery` — subnet discovery (ICMP/TCP/UDP/ARP)
- `ServiceDetector` — banner grabbing untuk 13 layanan
- `OSDetector` — estimasi OS via TTL + port + banner heuristics
- `DNSTools` — query A/AAAA/MX/NS/TXT/CNAME + reverse lookup + subdomain check
- `Traceroute` — path tracking cross-platform
- `SubnetTools` — CIDR info + host enumeration + IP attribute check
- `WHOISTools` — WHOIS domain query
- CLI dengan 17 opsi via Click + Rich
- Report export: JSON, CSV, HTML (dark theme), Markdown
- Authorization-first validation system
- Thread-safe RateLimiter
- Scan profiles: quick, normal, full, custom
- Unit tests: validator, subnet, port scanner, exporter
- Published ke PyPI sebagai `ScanNet`

---

## 18. Referensi & Sumber Daya

### Dokumentasi Dependencies

| Library | Versi | Dokumentasi |
|---|---|---|
| Click | ≥8.0.0 | https://click.palletsprojects.com |
| Rich | ≥12.0.0 | https://rich.readthedocs.io |
| dnspython | ≥2.2.0 | https://www.dnspython.org |
| requests | ≥2.27.0 | https://requests.readthedocs.io |
| python-whois | ≥0.7.3 | https://pypi.org/project/python-whois |
| tabulate | ≥0.8.9 | https://pypi.org/project/tabulate |

### Referensi Teknis Jaringan

| Topik | RFC / Sumber |
|---|---|
| TCP/IP | RFC 793 (TCP), RFC 791 (IP) |
| ICMP | RFC 792 |
| UDP | RFC 768 |
| DNS | RFC 1034, 1035 |
| Port Numbers | IANA Service Name & Port Registry |
| CIDR Notation | RFC 4632 |
| WHOIS | RFC 3912 |
| ARP | RFC 826 |
| Traceroute | RFC 1393 |

### Link Terkait

- **PyPI Package:** https://pypi.org/project/ScanNet/
- **GitHub Repository:** https://github.com/user/netscan
- **IANA Port Registry:** https://www.iana.org/assignments/service-names-port-numbers
- **Python ipaddress Module:** https://docs.python.org/3/library/ipaddress.html
- **Python socket Module:** https://docs.python.org/3/library/socket.html
- **Python concurrent.futures:** https://docs.python.org/3/library/concurrent.futures.html

---

<div align="center">

---

**Dokumentasi ini mencakup 100% kode ScanNet v0.1.0**

*Dibuat dengan teliti oleh NetScan Team*  
*Lisensi MIT © 2026 NetScan Team*

---

</div>
