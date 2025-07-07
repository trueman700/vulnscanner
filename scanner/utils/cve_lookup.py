import requests
import os
import re
import logging
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from time import sleep
from urllib.parse import quote
from pathlib import Path
from dotenv import load_dotenv
import hashlib
import time

# Initialize logging
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
API_KEY = os.getenv("NVD_API_KEY")
REQUEST_DELAY = 6  # Seconds between requests (NVD requires 6s between requests)
MAX_RETRIES = 3
CACHE_DIR = Path(".cve_cache")
CACHE_EXPIRY_DAYS = 7

# Enhanced local vulnerability database
LOCAL_VULN_DB = {
    'apache:http_server': {
        '2.4.58': {
            'cves': [
                {
                    'id': 'CVE-2023-25690',
                    'description': 'Apache HTTP Server mod_proxy vulnerability',
                    'cvss_v3': 9.8,
                    'references': [
                        'https://httpd.apache.org/security/vulnerabilities_24.html'
                    ]
                },
                {
                    'id': 'CVE-2023-27522',
                    'description': 'Apache HTTP Server HTTP/2 memory corruption',
                    'cvss_v3': 8.6
                }
            ]
        }
    },
    'postgresql:postgresql': {
        '9.6.0': {
            'cves': [
                {
                    'id': 'CVE-2016-5423',
                    'description': 'PostgreSQL privilege escalation',
                    'cvss_v3': 7.8
                },
                {
                    'id': 'CVE-2016-5424',
                    'description': 'PostgreSQL memory disclosure',
                    'cvss_v3': 6.5
                }
            ]
        }
    }
}

# Initialize cache directory
CACHE_DIR.mkdir(exist_ok=True)

class CVELookup:
    def __init__(self):
        self.rate_limited = False
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityScanner/1.0',
            'Accept': 'application/json'
        })
        if API_KEY:
            self.session.headers['apiKey'] = API_KEY

    def clean_version(self, version: str) -> str:
        """Sanitize and standardize version strings."""
        if not version:
            return ""
        
        # Remove special characters and take first part
        version = re.sub(r'[^a-zA-Z0-9._-]', '', str(version).split()[0])
        return version.split('/')[0]  # Handle cases like '1.2.3/4'

    def generate_cpe(self, service: str, version: str) -> Optional[str]:
        """
        Generate valid CPE 2.3 string with enhanced service mapping.
        
        Args:
            service: Service name (e.g., 'http', 'ssh')
            version: Version string
            
        Returns:
            Properly formatted CPE string or None if invalid
        """
        if not service or not version:
            return None
            
        service = service.lower().strip()
        version = self.clean_version(version)
        
        # Expanded service mappings
        cpe_mappings = {
            'http': 'apache:http_server',
            'https': 'apache:http_server',
            'ssh': 'openssh:openssh',
            'ftp': 'vsftpd:vsftpd',
            'postgresql': 'postgresql:postgresql',
            'mysql': 'mysql:mysql',
            'smb': 'samba:samba',
            'redis': 'redis:redis',
            'nginx': 'nginx:nginx',
            'iis': 'microsoft:iis',
            'tomcat': 'apache:tomcat',
            'wordpress': 'wordpress:wordpress'
        }
        
        base_product = cpe_mappings.get(service, f"*:{service.replace(' ', '_')}")
        return f"cpe:2.3:a:{base_product}:{version}:*:*:*:*:*:*:*"

    def _get_cache_key(self, cpe: str) -> Path:
        """Generate cache file path from CPE string"""
        hash_key = hashlib.md5(cpe.encode()).hexdigest()
        return CACHE_DIR / f"{hash_key}.json"

    def _load_from_cache(self, cpe: str) -> Optional[Dict]:
        """Load cached CVE data if available and fresh"""
        cache_file = self._get_cache_key(cpe)
        
        if not cache_file.exists():
            return None
            
        file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
        if file_age > timedelta(days=CACHE_EXPIRY_DAYS):
            return None
            
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to read cache file {cache_file}: {str(e)}")
            return None

    def _save_to_cache(self, cpe: str, data: Dict) -> None:
        """Save CVE data to cache"""
        cache_file = self._get_cache_key(cpe)
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f)
        except IOError as e:
            logger.warning(f"Failed to write cache file {cache_file}: {str(e)}")

    def query_nvd_api(self, cpe: str, retry_count: int = 0) -> Optional[Dict]:
        """
        Query NVD API with enhanced error handling and caching.
        
        Args:
            cpe: CPE 2.3 string
            retry_count: Current retry attempt
            
        Returns:
            JSON response from NVD API or None if failed
        """
        if self.rate_limited:
            logger.debug("Skipping API query due to rate limiting")
            return None
            
        if retry_count >= MAX_RETRIES:
            logger.warning(f"Max retries reached for CPE: {cpe}")
            return None
        
        # Check cache first
        cached_data = self._load_from_cache(cpe)
        if cached_data:
            logger.debug(f"Using cached data for CPE: {cpe}")
            return cached_data
            
        try:
            encoded_cpe = quote(cpe, safe='')
            url = f"{NVD_API_URL}?cpeMatchString={encoded_cpe}"
            
            logger.debug(f"Querying NVD API for CPE: {cpe}")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self._save_to_cache(cpe, data)
                return data
            elif response.status_code == 403:
                logger.warning("NVD API rate limit reached")
                self.rate_limited = True
                sleep(REQUEST_DELAY * 2)
                return None
            elif response.status_code == 429:
                logger.warning("NVD API rate limit reached")
                time.sleep(REQUEST_DELAY)
                return self.query_nvd_api(cpe, retry_count + 1)
            else:
                logger.warning(f"NVD API returned status {response.status_code}")
                sleep(REQUEST_DELAY)
                return self.query_nvd_api(cpe, retry_count + 1)
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for CPE {cpe}: {str(e)}")
            sleep(REQUEST_DELAY)
            return self.query_nvd_api(cpe, retry_count + 1)

    def check_local_db(self, service: str, version: str) -> Optional[Dict]:
        """
        Enhanced local vulnerability database lookup with more detailed results.
        
        Args:
            service: Service name
            version: Version string
            
        Returns:
            Dictionary with vulnerability details if found, None otherwise
        """
        service_key = service.lower().replace(' ', '_')
        version_clean = self.clean_version(version)
        
        for db_key in LOCAL_VULN_DB:
            if service_key in db_key:
                if version_clean in LOCAL_VULN_DB[db_key]:
                    return LOCAL_VULN_DB[db_key][version_clean]
        return None

    def parse_cve_items(self, cve_data: Dict) -> List[Dict]:
        """
        Enhanced CVE item parsing with more comprehensive data extraction.
        
        Args:
            cve_data: Raw NVD API response
            
        Returns:
            List of parsed CVEs with detailed information
        """
        if not cve_data or 'result' not in cve_data:
            return []
            
        cves = []
        for item in cve_data['result']['CVE_Items']:
            try:
                cve_id = item['cve']['CVE_data_meta']['ID']
                
                # Get both CVSS v3 and v2 scores
                cvss_v3 = item['impact'].get('baseMetricV3', {}).get('cvssV3', {})
                cvss_v2 = item['impact'].get('baseMetricV2', {}).get('cvssV2', {})
                
                # Get references
                references = [
                    ref['url'] for ref in item['cve']['references']['reference_data']
                ]
                
                cves.append({
                    'id': cve_id,
                    'score': float(cvss_v3.get('baseScore', cvss_v2.get('baseScore', 0.0))),
                    'severity': self.get_severity(cvss_v3.get('baseScore', cvss_v2.get('baseScore', 0.0))),
                    'description': item['cve']['description']['description_data'][0]['value'],
                    'published': item['publishedDate'],
                    'last_modified': item['lastModifiedDate'],
                    'references': references,
                    'cvss_v3': cvss_v3,
                    'cvss_v2': cvss_v2,
                    'source': 'nvd'
                })
            except (KeyError, ValueError) as e:
                logger.warning(f"Error parsing CVE item: {str(e)}")
                continue
                
        return cves

    def get_severity(self, score: float) -> str:
        """Convert CVSS score to severity level with more granular thresholds."""
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        elif score > 0.0:
            return 'low'
        return 'none'

    def fetch_cves(self, service: str, version: str) -> List[Dict]:
        """
        Enhanced CVE lookup with multiple fallback strategies.
        
        Args:
            service: Service name (e.g., 'Apache httpd')
            version: Version string
            
        Returns:
            List of CVEs with detailed information
        """
        if not service or service.lower() in ['tcpwrapped', 'unknown']:
            return []
            
        # First try local database
        local_result = self.check_local_db(service, version)
        if local_result:
            logger.info(f"Using local DB for {service} {version}")
            return [
                {
                    'id': cve['id'],
                    'score': cve.get('cvss_v3', 7.0),
                    'severity': self.get_severity(cve.get('cvss_v3', 7.0)),
                    'description': cve.get('description', f"Known vulnerability in {service} {version}"),
                    'references': cve.get('references', []),
                    'source': 'local_db'
                }
                for cve in local_result['cves']
            ]
        
        # Generate CPE and query NVD
        cpe = self.generate_cpe(service, version)
        if not cpe:
            return []
            
        # Respect rate limits
        if not self.rate_limited:
            sleep(REQUEST_DELAY)
            
        api_response = self.query_nvd_api(cpe)
        if api_response:
            fetched_cves = self.parse_cve_items(api_response)
            # Ensure each CVE dict has 'id', 'score', and 'severity'
            cves = []
            for cve in fetched_cves:
                cves.append({
                    'id': cve.get('id'),
                    'score': cve.get('cvss_v3', cve.get('score', 0.0)),
                    'severity': self.get_severity(cve.get('cvss_v3', cve.get('score', 0.0))),
                    'description': cve.get('description', ''),
                    'references': cve.get('references', [])
                })
            return cves
            
        return []

    def clear_cache(self) -> None:
        """Clear all cached CVE data"""
        for cache_file in CACHE_DIR.glob("*.json"):
            try:
                cache_file.unlink()
            except OSError as e:
                logger.warning(f"Failed to delete cache file {cache_file}: {str(e)}")

# Global instance for convenience
cve_lookup = CVELookup()

# Maintain backwards compatibility with direct function calls
def fetch_cves(service: str, version: str) -> List[Dict]:
    return cve_lookup.fetch_cves(service, version)