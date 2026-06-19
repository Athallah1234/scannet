import subprocess
import platform

def icmp_ping(host: str, timeout: float = 2.0) -> bool:
    """Performs an ICMP ping using the OS ping command to avoid raw socket admin requirements."""
    # Convert timeout to seconds/milliseconds based on OS
    timeout_ms = int(timeout * 1000)
    
    if platform.system().lower() == "windows":
        # -n: count, -w: timeout in ms
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        # -c: count, -W: timeout in seconds
        timeout_sec = max(1, int(timeout))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), host]
        
    try:
        # Run command silently
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout + 1.0
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False
