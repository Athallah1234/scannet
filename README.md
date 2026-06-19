# NetScan (Network Scanning Library)

NetScan adalah sebuah library dan command line interface (CLI) Python yang didesain secara khusus untuk kebutuhan pembelajaran (educational), audit keamanan jaringan internal, inventarisasi perangkat, dan pemantauan keamanan yang legal/authorized-only.

## Fitur Utama

- **Validasi Target Ketat**: Memvalidasi IP address, domain, subnet range CIDR, port, dan port range. Secara default, pemindaian ke target IP publik akan diblokir kecuali user mengaktifkan flag `allow_public=True`.
- **Host Discovery**: Pencarian host aktif di subnet jaringan internal menggunakan ping sweep, ICMP ping, TCP ping, UDP ping, dan ARP lookup lokal.
- **Port Scanning**: Pencarian port terbuka (TCP Connect scan, UDP basic scan) dengan timeout & thread count yang dapat dikonfigurasi.
- **Service Detection**: Banner grabbing aman untuk berbagai protokol populer (HTTP, HTTPS, SSH, FTP, SMTP, DNS, MySQL, PostgreSQL, Redis, MongoDB, RDP, SMB) tanpa melakukan serangan brute-force atau eksploitasi celah keamanan.
- **OS Fingerprinting Heuristik**: Estimasi Operating System berdasarkan nilai TTL (Time To Live), port listening, dan informasi banner.
- **DNS & Traceroute Tools**: DNS lookup lengkap, reverse DNS PTR resolution, traceroute aman, dan pengecekan subdomain berdasarkan list kustom.
- **Subnet Tools**: Perhitungan range IP, broadcast address, private/public subnet checks, loopback/multicast check.
- **Reporting Modular**: Ekspor laporan hasil scanning ke format JSON, CSV, HTML, dan Markdown.

---

## Instalasi

Pastikan Anda menggunakan Python 3.10 ke atas.

```bash
# Clone repository
git clone https://github.com/user/scannet.git
cd netscan

# Install menggunakan mode edit (-e) agar siap dikembangkan
pip install -e .
```

---

## Penggunaan CLI

Setiap aksi pemindaian membutuhkan konfirmasi autorisasi legal melalui flag `--yes-authorized`.

```bash
# Bantuan umum CLI
netscan --help

# Pindai port default (top 100) pada localhost
netscan --target 127.0.0.1 --yes-authorized

# Pindai port range spesifik dengan deteksi service dan OS
netscan --target 127.0.0.1 --ports 22,80,443 --service-detect --os-detect --yes-authorized

# Subnet Host Discovery (Ping Sweep)
netscan --subnet 192.168.1.0/24 --discover --yes-authorized

# DNS Record Lookup
netscan --target google.com --dns --allow-public --yes-authorized

# Traceroute Path Analysis
netscan --target 127.0.0.1 --traceroute --yes-authorized

# Ekspor hasil scan ke file HTML
netscan --target 127.0.0.1 --ports 1-1000 --export html --output report.html --yes-authorized
```

---

## Penggunaan Python API

### 1. Port Scan & Service Detection

```python
from scannet import NetScanner

# Inisialisasi scanner
scanner = NetScanner(
    target="127.0.0.1",
    timeout=2.0,
    threads=20,
    rate_limit=10, # 10 request per detik
    authorized=True
)

# Jalankan scan port dengan service detection
result = scanner.scan_ports("22,80,443", detect_services=True, detect_os=True)
print(result)
```

### 2. Network Discovery Sweep

```python
from scannet import NetworkDiscovery

discovery = NetworkDiscovery(
    subnet="192.168.1.0/24",
    authorized=True
)

hosts = discovery.discover()
print("Host Aktif:", hosts)
```

---

## Contoh Hasil Output (Terminal)

```text
==================================================
                   NETSCAN REPORT                 
==================================================
Scan Duration: 0.85s
Total Hosts Discovered: 1
Total Open Ports: 2
--------------------------------------------------

Host: 127.0.0.1 (localhost)
  Estimated OS: Linux/Unix (Estimated, score=3)
+--------+--------+-----------+-------------------------+
|   Port | State  | Service   | Banner/Details          |
+========+========+===========+=========================+
|     22 | open   | ssh       | SSH-2.0-OpenSSH_8.2p1   |
+--------+--------+-----------+-------------------------+
|     80 | open   | http      | nginx/1.18.0 (Status:200)|
+--------+--------+-----------+-------------------------+
```

---

## Batasan Keamanan & Guardrails

Library ini dibangun dengan prinsip pertahanan dan audit internal. Di dalamnya terdapat fitur keamanan terprogram:
1. **Pernyataan Otorisasi Wajib**: Scan tidak akan berjalan tanpa `authorized=True` / `--yes-authorized`.
2. **Blokir Target Publik**: Target IP publik diblokir secara default untuk mencegah penyalahgunaan tak sengaja. Harus dilewati dengan `allow_public=True` / `--allow-public`.
3. **No Exploit & No Brute-Force**: Library ini tidak mengirim payload eksploitasi celah keamanan, bypass firewall, DDoS flooding, brute force password, ataupun stealth scan.
4. **Rate Limiting**: Kecepatan request per detik dapat dibatasi melalui parameter `rate_limit`.

---

## Legal Disclaimer

> [!WARNING]
> NetScan dibuat khusus untuk tujuan edukasi pembelajaran keamanan siber dan pemantauan resmi aset jaringan internal sendiri. Developer tidak bertanggung jawab atas segala kerusakan, kehilangan data, tuntutan hukum, atau penyalahgunaan yang melanggar hukum setempat yang disebabkan oleh penggunaan tool ini. Anda wajib memiliki izin tertulis resmi sebelum memindai jaringan yang bukan milik Anda pribadi.

---

## Kontribusi & Lisensi

Kontribusi dipersilakan dengan membuka Pull Request.
Berlisensi di bawah **MIT License**.
