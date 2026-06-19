import socket

def udp_ping(host: str, port: int = 123, timeout: float = 2.0) -> bool:
    """Sends a basic UDP packet to verify if the port might be active/filtered or closed."""
    # We send a dummy packet. If we receive ICMP Destination Unreachable (handled by OS or socket error), it's closed.
    # If no response, it's open/filtered.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # Send empty payload
        sock.sendto(b"", (host, port))
        # Attempt to read to see if there's any response (rare for random ports, but checks if port responds)
        data, addr = sock.recvfrom(1024)
        return True
    except socket.timeout:
        # Host exists or filtered
        return True
    except ConnectionResetError:
        # Port closed
        return False
    except OSError:
        return False
    finally:
        sock.close()
