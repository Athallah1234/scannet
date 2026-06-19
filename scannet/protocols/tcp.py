import socket

def tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    """Verifies if a TCP port is open by attempting a full connection handshake."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
