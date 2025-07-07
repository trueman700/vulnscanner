from cvss import CVSS3
import requests
import logging

class AdvancedPrioritizer:
    def __init__(self, scan_data):
        self.scan_data = scan_data
        self.exploit_db_url = "https://exploit-db.com/search"

    def _get_cvss_base_score(self, cve: dict) -> float:
        """Safely extract CVSS base score"""
        try:
            # Handle both NVD API response and our normalized format
            if hasattr(cve, 'impact'):
                return float(cve.impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0))
            return float(getattr(cve, 'cvss_score', 0))
        except (TypeError, ValueError):
            return 0.0

    def _get_exploit_availability(self, cve_id: str) -> bool:
        """Check if exploit exists (mock version for testing)"""
        known_exploits = {
            'CVE-2021-41773': True,  # Apache path traversal
            'CVE-2021-3449': True    # OpenSSL DoS
        }
        return known_exploits.get(cve_id, False)

    def _calculate_composite_score(self, cve: dict) -> float:
        """Enhanced scoring without CVSS3 vector requirement"""
        base_score = self._get_cvss_base_score(cve)
        exploit_available = self._get_exploit_availability(getattr(cve, 'id', None) or cve.get('id'))
        
        # Weighted formula: 60% CVSS, 30% exploit, 10% service criticality
        return (base_score * 0.6) + (10 * 0.3 if exploit_available else 0) + 2  # 2 = base asset value

    def _get_host_ip(self, host):
        """Safely get host IP from object or dict"""
        if isinstance(host, dict):
            return host.get('ip', 'unknown')
        return getattr(host, 'ip', None) or getattr(host, 'address', None) or 'unknown'

    def _get_port_info(self, port):
        """Safely get port information from object or dict"""
        if isinstance(port, dict):
            return {
                'number': port.get('port', 0),
                'service': port.get('service', 'unknown'),
                'cves': port.get('cves', [])
            }
        else:
            return {
                'number': getattr(port, 'port', 0),
                'service': getattr(port, 'service', 'unknown'),
                'cves': getattr(port, 'cves', [])
            }

    def prioritize(self) -> list:
        """Generate prioritized list with remediation"""
        prioritized = []
        # If scan_data is a tuple (nmap_hosts, openvas_findings), flatten it
        if isinstance(self.scan_data, tuple):
            hosts = []
            for part in self.scan_data:
                if isinstance(part, list):
                    hosts.extend(part)
                elif isinstance(part, dict):
                    hosts.append(part)
        elif isinstance(self.scan_data, list):
            hosts = self.scan_data
        else:
            hosts = [self.scan_data]

        for host in hosts:
            # Skip if host is not a dict or object with ports
            if not (isinstance(host, dict) or hasattr(host, 'ports')):
                continue
            host_ip = self._get_host_ip(host)
            # Robustly get ports
            ports = []
            if isinstance(host, dict):
                ports = host.get('ports', [])
            elif hasattr(host, 'ports'):
                ports = getattr(host, 'ports', [])
            # Defensive: skip if ports is not a list
            if not isinstance(ports, list):
                continue
            for port in ports:
                port_info = self._get_port_info(port)
                for cve in port_info['cves']:
                    cve_id = getattr(cve, 'id', None) or cve.get('id')
                    score = self._calculate_composite_score(cve)
                    prioritized.append({
                        'host': host_ip,
                        'port': port_info['number'],
                        'service': port_info['service'],
                        'cve': cve_id,
                        'cvss_score': self._get_cvss_base_score(cve),
                        'exploit_available': self._get_exploit_availability(cve_id),
                        'composite_score': round(score, 1),
                        'recommendation': self._generate_remediation(cve, port_info['service'])
                    })
        return sorted(prioritized, key=lambda x: x['composite_score'], reverse=True)

    def _generate_remediation(self, cve: dict, service: str) -> str:
        """Generate actionable remediation steps"""
        remediation_db = {
            'http': [
                "Update to latest stable version",
                "Disable directory listing",
                "Implement WAF rules"
            ],
            'postgresql': [
                "Apply security patches",
                "Restrict network access",
                "Enable encryption"
            ],
            'ipp': [
                "Disable IPP if unused",
                "Update CUPS package",
                "Restrict to localhost"
            ]
        }
        default_actions = [
            f"Apply patch for {getattr(cve, 'id', None) or cve.get('id', 'CVE')}",
            "Restrict network access",
            "Monitor for exploitation attempts"
        ]
        return "\n".join(remediation_db.get(service.lower(), default_actions))