import socket

def check_ftp(host: str, port: int = 21, timeout: float = 2.0) -> str:
    """Connects to FTP and grabs the service greeting banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner.startswith("220") or "ftp" in banner.lower():
                return banner
    except Exception:
        pass
    return ""
