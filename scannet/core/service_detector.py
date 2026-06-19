import socket
from scannet.protocols.http import check_http
from scannet.protocols.https import check_https
from scannet.protocols.ssh import check_ssh
from scannet.protocols.ftp import check_ftp
from scannet.protocols.smtp import check_smtp
from scannet.protocols.dns import check_dns
from scannet.protocols.snmp import check_snmp
from scannet.utils.logger import get_logger

logger = get_logger()

class ServiceDetector:
    def __init__(self, target: str, timeout: float = 2.0):
        self.target = target
        self.timeout = timeout

    def detect_service(self, port: int) -> dict:
        """Attempts to securely identify service running on specified port using banner grabs and signatures."""
        service = "unknown"
        banner = ""
        
        # Guard rails: do not attempt active exploitation/brute-force
        try:
            if port in [80, 8080]:
                banner = check_http(self.target, port, self.timeout)
                if banner:
                    service = "http"
            elif port in [443, 8443]:
                banner = check_https(self.target, port, self.timeout)
                if banner:
                    service = "https"
            elif port == 22:
                banner = check_ssh(self.target, port, self.timeout)
                if banner:
                    service = "ssh"
            elif port == 21:
                banner = check_ftp(self.target, port, self.timeout)
                if banner:
                    service = "ftp"
            elif port == 25:
                banner = check_smtp(self.target, port, self.timeout)
                if banner:
                    service = "smtp"
            elif port == 53:
                banner = check_dns(self.target, port, self.timeout)
                if banner:
                    service = "dns"
            elif port == 161:
                banner = check_snmp(self.target, port, self.timeout)
                if banner:
                    service = "snmp"
            elif port == 3306:
                # MySQL protocol handshake
                banner = self._probe_mysql(port)
                if banner:
                    service = "mysql"
            elif port == 5432:
                # PostgreSQL
                banner = self._probe_postgres(port)
                if banner:
                    service = "postgresql"
            elif port == 6379:
                # Redis
                banner = self._probe_redis(port)
                if banner:
                    service = "redis"
            elif port == 27017:
                # MongoDB
                banner = self._probe_mongodb(port)
                if banner:
                    service = "mongodb"
            elif port == 3389:
                service = "rdp"
                banner = "Remote Desktop Protocol"
            elif port == 445:
                service = "smb"
                banner = "Microsoft DS SMB"
            else:
                # Generic banner grab
                banner = self._generic_banner_grab(port)
                if banner:
                    service = self._infer_service_from_banner(banner)
        except Exception as e:
            logger.debug(f"Service detection failed on port {port}: {e}")
            
        return {"service": service, "banner": banner}

    def _generic_banner_grab(self, port: int) -> str:
        try:
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                # Wait up to 1 second for standard service greeting first
                sock.settimeout(1.0)
                try:
                    return sock.recv(512).decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    # Send a generic payload if no banner received
                    sock.sendall(b"\r\n\r\n")
                    return sock.recv(512).decode('utf-8', errors='ignore').strip()
        except Exception:
            return ""

    def _infer_service_from_banner(self, banner: str) -> str:
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return "ssh"
        if "ftp" in banner_lower:
            return "ftp"
        if "smtp" in banner_lower:
            return "smtp"
        if "http" in banner_lower:
            return "http"
        if "amqp" in banner_lower:
            return "amqp"
        return "unknown"

    def _probe_mysql(self, port: int) -> str:
        try:
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                data = sock.recv(256)
                if len(data) > 5 and b"mysql" in data.lower():
                    # Parse version from greeting packet
                    version_start = 5
                    version_end = data.find(b"\x00", version_start)
                    if version_end != -1:
                        return f"MySQL {data[version_start:version_end].decode('utf-8', errors='ignore')}"
                    return "MySQL Service"
        except Exception:
            pass
        return ""

    def _probe_postgres(self, port: int) -> str:
        try:
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                # SSL Request packet: length 8, code 80877103
                sock.sendall(bytes.fromhex("0000000804d2162f"))
                res = sock.recv(1)
                if res in [b'S', b'N']:
                    return "PostgreSQL Database Service"
        except Exception:
            pass
        return ""

    def _probe_redis(self, port: int) -> str:
        try:
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                sock.sendall(b"PING\r\n")
                data = sock.recv(64)
                if b"PONG" in data or b"NOAUTH" in data:
                    return "Redis Key-Value Database"
        except Exception:
            pass
        return ""

    def _probe_mongodb(self, port: int) -> str:
        try:
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                # Simple OP_QUERY message to admin.$cmd
                # query {"isMaster": 1}
                payload = bytes.fromhex(
                    "3a000000a400000000000000d40700000000000061646d696e2e24636d640000000000ffffffff190000001069734d6173746572000100000000"
                )
                sock.sendall(payload)
                data = sock.recv(256)
                if len(data) > 0 and b"ismaster" in data.lower():
                    return "MongoDB Database Server"
        except Exception:
            pass
        return ""
