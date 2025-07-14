import requests

def clean_version(version: str) -> str:
    """Remove extra info from version strings, e.g. '1.2.3 (beta)' -> '1.2.3'"""
    return version.split()[0] if version else ""

def get_cpe(service: str, version: str) -> str:
    """Return a simple CPE string for a service and version."""
    if service == "http":
        return f"cpe:2.3:a:*:apache:http_server:{version}"
    return f"cpe:2.3:a:*:{service}:{version}"

def fetch_cves(service: str, version: str):
    """
    Dummy implementation for testing.
    In production, this should query the NVD or another CVE database.
    """
    # Example: Simulate an API call (replace with real logic as needed)
    return {"result": {"CVE_Items": []}}