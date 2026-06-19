import socket

def check_ssh(host: str, port: int = 22, timeout: float = 2.0) -> str:
    """Connects to SSH and grabs the protocol greeting banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # Read first line
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if "SSH" in banner:
                return banner
    except Exception:
        pass
    return ""
