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
from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path
from dataclasses import asdict

# Local imports
from scanner1.database import ScanDatabase
from scanner1.utils.cve_lookup import CVELookup
from scanner1.utils.nmap_parser import parse_nmap_results
from scanner1.utils.scanner import clean_version, get_cpe, fetch_cves  # <--- Use these imports

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

# Load environment variables
load_dotenv()

class VulnerabilityScanner:
    def __init__(self):
        self.db = ScanDatabase()
        self.cve_lookup = CVELookup()
        self.nmap_scanner = nmap.PortScanner()

    def run_scan(self, target: str) -> List:
        """Perform comprehensive vulnerability scan with enhanced detection"""
        try:
            logger.info(f"Scanning {target}...")
            scan_args = self._get_scan_arguments(target)
            self.nmap_scanner.scan(hosts=target, arguments=scan_args)
            if not self.nmap_scanner.all_hosts():
                return []
            hosts = parse_nmap_results(self.nmap_scanner)
            # Populate CVEs for each port
            for host in hosts:
                for port in host.ports:
                    port.cves = self.cve_lookup.fetch_cves(port.service, getattr(port, 'version', ''))
            return hosts
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}", exc_info=True)
            return None

    def _get_scan_arguments(self, target: str) -> str:
        """Determine optimal Nmap arguments based on target"""
        base_args = '-sV -T4 --open'
        
        # Add OS detection for single hosts
        #if not any(c in target for c in ['-', ',', ' ']):
            #base_args += ' -O'
            
        # Add script scanning if not disabled
        if not os.getenv('DISABLE_NSE'):
            base_args += ' --script vulners,vuln'
            
        return base_args

    def process_results(self, scan_results: List[Dict]) -> Dict:
        """Process raw scan results into structured report"""
        if not scan_results:
            return None
            
        critical_vulns = self._prioritize_vulnerabilities(scan_results)
        
        return {
            'metadata': self._generate_metadata(scan_results),
            'statistics': self._generate_statistics(scan_results, critical_vulns),
            'hosts': scan_results,
            'vulnerabilities': critical_vulns
        }

    def _prioritize_vulnerabilities(self, scan_results: List[Dict]) -> List[Dict]:
        """Prioritize vulnerabilities based on risk assessment"""
        try:
            from phase2.engine.advanced_prioritizer import AdvancedPrioritizer
            prioritizer = AdvancedPrioritizer(scan_results)
        except ImportError:
            from phase2.engine.prioritizer import VulnerabilityPrioritizer
            prioritizer = VulnerabilityPrioritizer(scan_results)
            
        return prioritizer.prioritize()

    def _generate_metadata(self, scan_results: List) -> Dict:
        """Generate scan metadata"""
        return {
            'generated_at': datetime.now().isoformat(),
            'scan_target': scan_results[0].ip if scan_results else 'unknown',
            'scan_duration': self._calculate_scan_duration(scan_results),
            'scanner_version': '1.0',
            'scan_parameters': self.nmap_scanner.scaninfo()
        }

    def _calculate_scan_duration(self, scan_results: List) -> float:
        """Calculate scan duration from timestamps"""
        if not scan_results or not hasattr(scan_results[0], 'scan_time'):
            return 0.0
            
        try:
            start = datetime.fromisoformat(scan_results[0].scan_time)
            return (datetime.now() - start).total_seconds()
        except (ValueError, AttributeError):
            return 0.0

    def _generate_statistics(self, scan_results: List, vulns: List[Dict]) -> Dict:
        """Generate scan statistics"""
        return {
            'hosts_scanned': len(scan_results),
            'ports_scanned': sum(len(h.ports) for h in scan_results),
            'open_ports': sum(1 for h in scan_results for p in h.ports if p.state == 'open'),
            'services_identified': len({p.service for h in scan_results for p in h.ports}),
            'vulnerabilities_found': len(vulns),
            'critical_vulns': sum(1 for v in vulns if v['severity'] == 'critical'),
            'high_vulns': sum(1 for v in vulns if v['severity'] == 'high'),
            'medium_vulns': sum(1 for v in vulns if v['severity'] == 'medium'),
            'low_vulns': sum(1 for v in vulns if v['severity'] == 'low')
        }

    def save_to_database(self, scan_results: List) -> Optional[int]:
        """Save scan results to database"""
        if not scan_results:
            return None
            
        try:
            # Start new scan record
            target = scan_results[0].ip if len(scan_results) == 1 else 'Multiple hosts'
            scan_id = self.db.save_scan(target)
            
            # Save all hosts and vulnerabilities
            num_vulns = 0
            for host in scan_results:
                host_dict = asdict(host)
                # Map 'number' to 'port' for each port
                for port in host_dict.get('ports', []):
                    port['port'] = port.pop('number', None)
                host_id = self.db.save_host(scan_id, host_dict)
                num_vulns += sum(len(p.get('cves', [])) for p in host_dict.get('ports', []))
            
            # Complete scan record
            self.db.complete_scan(scan_id, len(scan_results), num_vulns)
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to save to database: {str(e)}")
            return None

    def generate_reports(self, report_data: Dict) -> bool:
        """Generate all output reports"""
        if not report_data:
            return False
            
        try:
            # Convert all Host objects to dicts for JSON serialization
            hosts = [asdict(h) if not isinstance(h, dict) else h for h in report_data.get('hosts', [])]
            report_data['hosts'] = hosts
            with open('scan_report.json', 'w') as f:
                json.dump(report_data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            return False

    def display_results(self, report_data: Dict) -> None:
        """Display results in console"""
        if not report_data:
            print("\nNo results to display")
            return

        print("\n=== SCAN SUMMARY ===")
        stats = report_data['statistics']
        print(f"\nTarget: {report_data['metadata']['scan_target']}")
        print(f"Duration: {stats['hosts_scanned']} hosts scanned in {report_data['metadata']['scan_duration']:.1f} seconds")
        print(f"Findings: {stats['vulnerabilities_found']} vulnerabilities ({stats['critical_vulns']} critical, {stats['high_vulns']} high)")

        # Print all hosts and their details
        print("\n=== HOSTS & SERVICES ===")
        for host in report_data['hosts']:
            print(f"\nHost: {host.get('ip', 'N/A')}")
            if host.get('hostname'):
                print(f"  Hostname: {host['hostname']}")
            if host.get('os'):
                os_info = host['os']
                print(f"  OS: {os_info.get('name', 'unknown')} (Accuracy: {os_info.get('accuracy', 'N/A')})")
            if host.get('ports'):
                print("  Open Ports:")
                for port in host['ports']:
                    print(f"    - {port.get('port', port.get('number', 'N/A'))}/{port.get('protocol', 'tcp')}: {port.get('service', 'unknown')} {port.get('version', '')} [{port.get('state', 'open')}]")
                    # List vulnerabilities for this port
                    if port.get('cves'):
                        for cve in port['cves']:
                            print(f"      * CVE: {cve.get('id', 'N/A')} | Score: {cve.get('score', 'N/A')} | Severity: {cve.get('severity', 'N/A')}")
                            print(f"        Desc: {cve.get('description', '')}")

        # Print all prioritized vulnerabilities
        if report_data['vulnerabilities']:
            print("\n=== PRIORITIZED VULNERABILITIES ===")
            for i, vuln in enumerate(report_data['vulnerabilities'], 1):
                print(f"\n{i}. {vuln.get('id', vuln.get('cve', 'N/A'))} ({vuln.get('severity', 'N/A').upper()})")
                print(f"   Host: {vuln.get('host', 'N/A')}:{vuln.get('port', 'N/A')}")
                print(f"   Service: {vuln.get('service', 'N/A')} {vuln.get('version', '')}")
                print(f"   CVSS: {vuln.get('score', vuln.get('cvss_score', 'N/A'))}")
                print(f"   Risk Score: {vuln.get('risk_score', 'N/A')}")
                print(f"   Recommendation: {vuln.get('recommendation', 'N/A')}")
                if vuln.get('description'):
                    print(f"   Description: {vuln['description']}")


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
                
            # Run scan
            scan_results = scanner.run_scan(target)
            if not scan_results:
                print("\nScan failed or no results returned")
                continue
                
            # Process results
            report_data = scanner.process_results(scan_results)
            
            # Save to database
            scanner.save_to_database(scan_results)
            
            # Generate reports
            scanner.generate_reports(report_data)
            
            # Display results
            scanner.display_results(report_data)
            
        except KeyboardInterrupt:
            print("\nScan cancelled by user")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")
            logger.exception("Error in scanner execution")

if __name__ == "__main__":
    # Add project root to path for module imports
    project_root = Path(__file__).parent.parent
    sys.path.append(str(project_root))
    
    try:
        main()
    except Exception as e:
        logger.critical(f"Scanner crashed: {str(e)}", exc_info=True)
        print("\nA critical error occurred. Check scanner.log for details.")