import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL certificate warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_https(host: str, port: int = 443, timeout: float = 2.0) -> str:
    """Checks if port serves HTTPS and returns Server header details."""
    url = f"https://{host}:{port}/"
    try:
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        server = response.headers.get("Server", "HTTPS Web Server")
        return f"{server} (Status: {response.status_code})"
    except requests.RequestException as e:
        return ""
