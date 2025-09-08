#!/usr/bin/env python3
from typing import List, Dict, Optional, Union 
import nmap
import requests
import os
import re
import json
import logging
import sys
from time import sleep
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()
from pathlib import Path
from dataclasses import asdict
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import socket
import getpass

from scanner1.utils.openvas_client import OpenVASClient

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self):
        self.nmap_scanner = nmap.PortScanner()
        self.openvas_client = OpenVASClient()  # <-- Add this

    def validate_target(self, target: str) -> bool:
        """Validate the target IP/hostname format"""
        try:
            # Check for IP address or hostname
            socket.inet_aton(target)
            return True
        except socket.error:
            try:
                socket.gethostbyname(target)
                return True
            except socket.error:
                return False

    def run_scan(self, target: str, scan_type: str = 'nmap') -> Optional[Dict]:
        """Perform comprehensive vulnerability scan"""
        try:
            if not self.validate_target(target):
                logger.error(f"Invalid target format: {target}")
                return None

            logger.info(f"Scanning {target} with {scan_type}...")
            
            results = {}
            
            if scan_type in ['nmap', 'both']:
                results['nmap'] = self._run_nmap_scan(target)

            if scan_type in ['openvas', 'both']:
                results['openvas'] = self._run_openvas_scan(target)

            return results
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}", exc_info=True)
            return None

    def _run_nmap_scan(self, target: str) -> dict:
        """Run Nmap scan and return results with vulnerability severity."""
        try:
            scan_args = self._get_scan_arguments(target)
            self.nmap_scanner.scan(hosts=target, arguments=scan_args)
            if not self.nmap_scanner.all_hosts():
                return {'error': 'No hosts found'}

            hosts_data = []
            for host in self.nmap_scanner.all_hosts():
                ports_data = []
                for port in self.nmap_scanner[host]['tcp']:
                    port_info = self.nmap_scanner[host]['tcp'][port]
                    service = port_info['name']
                    state = port_info['state']
                    scripts = port_info.get('script', {})
                    vulns = []
                    for script_name, script_output in scripts.items():
                        # Parse CVEs from script output (works for vulners, vuln, etc.)
                        cves = set()
                        for line in script_output.splitlines():
                            for word in line.split():
                                if word.startswith("CVE-"):
                                    cves.add(word.strip(",."))
                        for cve in cves:
                            cvss = self._fetch_cvss_score(cve)
                            severity = self._cvss_to_severity(cvss)
                            vulns.append({'cve': cve, 'cvss': cvss, 'severity': severity})
                    ports_data.append({
                        'port': port,
                        'state': state,
                        'service': service,
                        'vulnerabilities': vulns
                    })
                hosts_data.append({
                    'ip': host,
                    'status': self.nmap_scanner[host].state(),
                    'ports': ports_data
                })
            return {'hosts': hosts_data}
        except Exception as e:
            return {'error': str(e)}

    def _run_openvas_scan(self, target: str) -> Dict:
        """Run OpenVAS scan using the real OpenVAS client"""
        result = self.openvas_client.run_scan(target)
        if not result:
            logger.warning("OpenVAS scan failed or returned no results")
            return {'status': 'failed', 'findings': []}
        # If your OpenVASClient returns findings in a nested dict, adapt as needed:
        findings = result.get('findings', [])
        return {
            'status': result.get('status', 'completed'),
            'findings': findings,
            'summary': result.get('summary', {})
        }

    def _get_scan_arguments(self, target: str) -> str:
        """Determine optimal Nmap arguments"""
        base_args = '-sV -T4 --open'
        if os.geteuid() == 0 and not any(c in target for c in ['-', ',', ' ']):
            base_args += ' -O'  # OS detection for single hosts
        if not os.getenv('DISABLE_NSE'):
            base_args += ' --script vulners,vuln'
        return base_args

    def process_results(self, scan_results: dict) -> dict:
        """Process raw scan results into structured report"""
        if not scan_results:
            return None

        return {
            'metadata': {
                'scan_time': datetime.now(timezone.utc).isoformat(),
                'user': getpass.getuser(),
                'target': next(iter(scan_results.get('nmap', {}).get('hosts', [{}]))).get('ip', 'unknown')
            },
            'statistics': {
                'hosts_scanned': len(scan_results.get('nmap', {}).get('hosts', [])),
                'open_ports': sum(len(host.get('ports', [])) for host in scan_results.get('nmap', {}).get('hosts', []))
            },
            'results': scan_results
        }

    def generate_report(self, report_data: dict, format: str = 'console') -> bool:
        """Generate report in specified format"""
        if not report_data:
            return False

        if format == 'console':
            self._print_console_report(report_data)
        elif format == 'json':
            with open('scan_report.json', 'w') as f:
                json.dump(report_data, f, indent=2)
        elif format == 'pdf':
            self._generate_pdf_report(report_data)
        else:
            logger.error(f"Unsupported report format: {format}")
            return False

        return True

    def _print_console_report(self, report_data: dict):
        """Print report to console"""
        print("\n=== SCAN REPORT ===")
        print(f"\nScan Time: {report_data['metadata']['scan_time']}")
        print(f"Target: {report_data['metadata']['target']}")
        print(f"\nHosts Scanned: {report_data['statistics']['hosts_scanned']}")
        print(f"Open Ports Found: {report_data['statistics']['open_ports']}")

        if 'nmap' in report_data['results']:
            print("\nNmap Results:")
            for host in report_data['results']['nmap'].get('hosts', []):
                print(f"\nHost: {host['ip']} ({host['status']})")
                for port in host.get('ports', []):
                    print(f"  Port {port['port']}: {port['state']} - {port['service']}")
                    for vuln in port.get('vulnerabilities', []):
                        print(f"    CVE: {vuln['cve']} | CVSS: {vuln['cvss']} | Severity: {vuln['severity']}")

    def _generate_pdf_report(self, report_data: dict):
        """Generate PDF report (modern fpdf2 syntax)"""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", size=12)

        # Header
        pdf.cell(200, 10, text="Vulnerability Scan Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        pdf.cell(200, 10, text=f"Date: {report_data['metadata']['scan_time']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(200, 10, text=f"Target: {report_data['metadata'].get('target', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(200, 10, text=f"User: {report_data['metadata'].get('user', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(200, 10, text=f"Hosts Scanned: {report_data['statistics']['hosts_scanned']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(200, 10, text=f"Open Ports Found: {report_data['statistics']['open_ports']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Nmap Results
        nmap_results = report_data['results'].get('nmap', {})
        hosts = nmap_results.get('hosts', [])
        if hosts:
            pdf.set_font("helvetica", style="B", size=12)
            pdf.cell(200, 10, text="Nmap Results:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=11)
            for host in hosts:
                pdf.cell(200, 8, text=f"Host: {host['ip']} ({host['status']})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                for port in host.get('ports', []):
                    pdf.cell(200, 8, text=f"  Port {port['port']}: {port['state']} - {port['service']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    for vuln in port.get('vulnerabilities', []):
                        pdf.cell(200, 8, text=f"    CVE: {vuln['cve']} | CVSS: {vuln['cvss']} | Severity: {vuln['severity']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.cell(200, 10, text="No Nmap results.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # OpenVAS Results
        openvas_results = report_data['results'].get('openvas', {})
        findings = openvas_results.get('findings', [])
        if findings:
            pdf.set_font("helvetica", style="B", size=12)
            pdf.cell(200, 10, text="OpenVAS Results:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=11)
            for finding in findings:
                if isinstance(finding, dict):
                    pdf.cell(200, 8, text=f"Host: {finding.get('host', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.cell(200, 8, text=f"  Port: {finding.get('port', 'N/A')}, Severity: {finding.get('severity', 'N/A')}, Threat: {finding.get('threat', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.multi_cell(0, 8, text=f"  {finding.get('name', '')}: {finding.get('description', '')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                else:
                    pdf.cell(200, 8, text=f"OpenVAS finding: {str(finding)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font("helvetica", style="B", size=12)
            pdf.cell(200, 10, text="OpenVAS Results:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=11)
            pdf.cell(200, 10, text="No OpenVAS results.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.output("scan_report.pdf")

    def _fetch_cvss_score(self, cve_id: str) -> float:

        """Fetch CVSS score for a CVE from Vulners API or NVD API."""
        # Try Vulners first
        try:
            api_key = os.getenv('VULNERS_API_KEY')
            url = f"https://vulners.com/api/v3/search/id/?id={cve_id}"
            headers = {"X-Api-Key": api_key} if api_key else {}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                doc = data.get('data', {}).get('documents', {}).get(cve_id)
                if doc:
                    cvss = doc.get('cvss', 0)
                    if isinstance(cvss, dict):
                        return float(cvss.get('score', 0))
                    elif isinstance(cvss, (int, float)):
                        return float(cvss)
            else:
                logger.warning(f"Vulners API error for {cve_id}: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Vulners error for {cve_id}: {e}")

        # Try NVD as fallback
        try:
            nvd_api_key = os.getenv('NVD_API_KEY')
            url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
            headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get('result', {}).get('CVE_Items', [])
                if items:
                    metrics = items[0].get('impact', {})
                    cvss = metrics.get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
                    if cvss is not None:
                        return float(cvss)
                    cvss = metrics.get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore')
                    if cvss is not None:
                        return float(cvss)
            else:
                logger.warning(f"NVD API error for {cve_id}: {resp.status_code}")
        except Exception as e:
            logger.error(f"NVD error for {cve_id}: {e}")

        return 0.0

    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0:
            return "Low"
        return "None"

def main():
    """Main scanner execution"""
    print("\n=== Advanced Vulnerability Scanner ===")
    scanner = VulnerabilityScanner()
    
    while True:
        try:
            target = input("\nEnter target IP or range (or 'quit' to exit): ").strip()
            if target.lower() in ['quit', 'exit']:
                break
            if not target:
                print("Please enter a valid target")
                continue

            scan_type = input("Scan type? (nmap/openvas/both): ").strip().lower()
            while scan_type not in ['nmap', 'openvas', 'both']:
                print("Invalid scan type. Please enter 'nmap', 'openvas', or 'both'")
                scan_type = input("Scan type? (nmap/openvas/both): ").strip().lower()

            # Run scan
            scan_results = scanner.run_scan(target, scan_type)
            if not scan_results:
                print("\nScan failed or no results returned")
                continue
                
            # Process results
            report_data = scanner.process_results(scan_results)
            
            # Generate report
            report_format = input("Report format? (console/json/pdf): ").strip().lower()
            while report_format not in ['console', 'json', 'pdf']:
                print("Invalid format. Please enter 'console', 'json', or 'pdf'")
                report_format = input("Report format? (console/json/pdf): ").strip().lower()
                
            scanner.generate_report(report_data, report_format)
            
        except KeyboardInterrupt:
            print("\nScan cancelled by user")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")
            logger.exception("Error in scanner execution")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"Scanner crashed: {str(e)}", exc_info=True)
        print("\nA critical error occurred. Check scanner.log for details.")