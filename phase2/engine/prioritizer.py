import requests
from typing import List, Dict, Any
import logging

class VulnerabilityPrioritizer:
    def __init__(self, scan_results: List[Any]):
        self.scan_results = scan_results
        self.exploit_db_api = "https://exploit-db.com/api/v1/search"
        self.cve_api = "https://services.nvd.nist.gov/rest/json/cves/1.0"

    def _get_asset_criticality(self, ip: str) -> float:
        """Assign criticality score (0-1) based on IP role"""
        if ip == "192.168.1.1":
            return 0.9  # Router
        elif ip.startswith("192.168.1."):
            return 0.6  # Internal host
        return 0.3      # Unknown

    def _check_exploit_availability(self, cve_id: str) -> bool:
        try:
            response = requests.get(
                f"{self.exploit_db_api}?cve={cve_id}",
                timeout=3
            )
            return response.json().get('total', 0) > 0
        except Exception as e:
            logging.warning(f"Exploit DB check failed: {e}")
            return False

    def prioritize(self) -> List[Dict]:
        prioritized = []
        for host in self.scan_results:
            for port in getattr(host, 'ports', []):
                for cve in getattr(port, 'cves', []):
                    risk_score = self._calculate_risk_score(
                        cve.get('score', 0.0),
                        self._check_exploit_availability(cve.get('id', '')),
                        self._get_asset_criticality(getattr(host, 'ip', ''))
                    )
                    prioritized.append({
                        **cve,
                        'host': getattr(host, 'ip', ''),
                        'port': getattr(port, 'number', None),
                        'risk_score': risk_score,
                        'recommendation': self._generate_remediation(getattr(port, 'service', ''))
                    })
        return sorted(prioritized, key=lambda x: x['risk_score'], reverse=True)

    @staticmethod
    def _calculate_risk_score(cvss: float, has_exploit: bool, criticality: float) -> float:
        """Weighted risk formula"""
        return (cvss * 0.6) + (has_exploit * 0.3) + (criticality * 0.1)

    @staticmethod
    def _generate_remediation(service: str) -> str:
        remediation_db = {
            'http': "1. Update to latest version\n2. Enable WAF",
            'ssh': "1. Disable root login\n2. Enforce key-based auth"
        }
        return remediation_db.get(service.lower(), "Apply security patches")