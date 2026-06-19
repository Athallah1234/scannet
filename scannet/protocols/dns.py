import dns.resolver

def check_dns(host: str, port: int = 53, timeout: float = 2.0) -> str:
    """Performs a simple query to the target DNS server to check if it's open and responding."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [host]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        # Query root NS or localhost
        answers = resolver.resolve("localhost", "A")
        return f"DNS Server (Resolved localhost to {list(answers)[0]})"
    except Exception as e:
        # Even if resolution fails, if it's a dns error rather than connection failure, it might be open
        if "timeout" in str(e).lower() or "connection" in str(e).lower():
            return ""
        return "Responding DNS Server"
