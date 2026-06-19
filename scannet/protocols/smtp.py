import socket

def check_smtp(host: str, port: int = 25, timeout: float = 2.0) -> str:
    """Connects to SMTP and grabs the server greeting banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner.startswith("220") or "smtp" in banner.lower():
                return banner
    except Exception:
        pass
    return ""
