from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class Vulnerability:
    """Represents a security vulnerability"""
    id: str                   # CVE ID (e.g., "CVE-2021-1234")
    score: float              # CVSS score (0.0-10.0)
    severity: str             # critical/high/medium/low
    description: str          # Vulnerability description
    published: Optional[str] = None  # Publication date
    last_modified: Optional[str] = None  # Last modified date
    exploit_available: bool = False  # Is exploit publicly available?
    references: List[str] = None  # Reference URLs

@dataclass
class Port:
    """Represents a network port and its service"""
    number: int               # Port number (e.g., 80)
    protocol: str             # tcp/udp
    service: str              # Service name (e.g., "http")
    version: str              # Service version
    state: str                # open/closed/filtered
    cves: List[Vulnerability] # List of vulnerabilities
    scripts: Dict = None      # Nmap script output
    
    def __post_init__(self):
        if self.scripts is None:
            self.scripts = {}
        if self.cves is None:
            self.cves = []

@dataclass
class Host:
    """Represents a scanned host system"""
    ip: str                   # IP address
    hostname: str             # Hostname if available
    os: Dict                  # OS detection info
    ports: List[Port]         # List of ports
    mac: Optional[str] = None # MAC address if available
    
    def __post_init__(self):
        if self.ports is None:
            self.ports = []