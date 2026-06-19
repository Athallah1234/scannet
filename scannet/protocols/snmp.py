import socket

def check_snmp(host: str, port: int = 161, timeout: float = 2.0) -> str:
    """Sends a raw SNMP v2c sysDescr GetRequest to see if SNMP is active."""
    # ASN.1 encoded SNMP v2c GetRequest for community: public, OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
    payload = bytes.fromhex(
        "302c02010104067075626c6963a01f02041a2b3c4d0201000201003011300f060b2b060102010101000500"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, addr = sock.recvfrom(1024)
        if len(data) > 0:
            return "SNMP Service (Responding)"
    except Exception:
        pass
    finally:
        sock.close()
    return ""
