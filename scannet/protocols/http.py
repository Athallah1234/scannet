import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL certificate warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_http(host: str, port: int = 80, timeout: float = 2.0) -> str:
    """Checks if port serves HTTP and returns Server header details."""
    url = f"http://{host}:{port}/"
    try:
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        server = response.headers.get("Server", "HTTP Web Server")
        return f"{server} (Status: {response.status_code})"
    except requests.RequestException as e:
        return ""
