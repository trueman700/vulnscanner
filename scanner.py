#!/usr/bin/env python3
import os
import sys
import socket
import nmap
import requests
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum
import xml.etree.ElementTree as ET
from pathlib import Path
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import getpass
import concurrent.futures
import re
from urllib.parse import urlparse
import subprocess
import tempfile
import shutil
import signal
import time

# NEW: Import for Gemini AI
import google.generativeai as genai

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnscan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ScanType(Enum):
    NMAP = "nmap"
    OPENVAS = "openvas"
    HYBRID = "hybrid"

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

@dataclass
class Vulnerability:
    cve: str
    description: str
    cvss: float
    severity: Severity
    port: Optional[int] = None
    service: Optional[str] = None
    exploit_available: bool = False
    references: List[str] = None
    ai_analysis: Optional[str] = None # NEW: Field to store AI-generated analysis

@dataclass
class HostResult:
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    ports: List[Dict] = None
    vulnerabilities: List[Vulnerability] = None

class AdvancedVulnerabilityScanner:
    def __init__(self):
        self.nmap_scanner = nmap.PortScanner()
        self.session_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.temp_dir = tempfile.mkdtemp(prefix=f"vulnscan_{self.session_id}_")
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        
        # Load API keys from environment
        self.vulners_api_key = os.getenv('VULNERS_API_KEY')
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        self.shodan_api_key = os.getenv('SHODAN_API_KEY')

        # NEW: Initialize Gemini AI model
        self.gemini_api_key = os.getenv('GEMINI_API_KEY')
        self.gemini_model = None
        if self.gemini_api_key:
            try:
                genai.configure(api_key=self.gemini_api_key)
                self.gemini_model = genai.GenerativeModel("gemini-pro") # Consider "gemini-1.5-flash" for faster responses
                logger.info("Gemini AI model initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini AI model: {e}. Gemini AI features will be disabled.")
                self.gemini_api_key = None # Disable if initialization fails
        else:
            logger.warning("GEMINI_API_KEY environment variable not set. Gemini AI features will be disabled.")


        # Initialize OpenVAS/GVM client if configured
        self.openvas_enabled = False
        if os.getenv('OPENVAS_HOST'):
            try:
                from scanner.utils.openvas_client import OpenVASClient
                self.openvas_client = OpenVASClient(
                    host=os.getenv('OPENVAS_HOST'),
                    username=os.getenv('OPENVAS_USER', 'admin'),
                    password=os.getenv('OPENVAS_PASS', '')
                )
                self.openvas_enabled = True
                logger.info("OpenVAS client initialized successfully")
            except ImportError:
                logger.warning("python-gvm package not installed, OpenVAS disabled")
            except Exception as e:
                logger.error(f"OpenVAS initialization failed: {str(e)}")
                self.openvas_enabled = False
        else:
            logger.info("OpenVAS not configured (OPENVAS_HOST not set)")

    def __del__(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Validate target with multiple checks"""
        try:
            # Check if it's a URL
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                target = parsed.netloc.split(':')[0]
            
            # IP validation
            try:
                socket.inet_aton(target)
                return True, "ip"
            except socket.error:
                pass
                
            # Hostname validation
            try:
                socket.gethostbyname(target)
                return True, "hostname"
            except socket.error:
                pass
                
            # CIDR range validation
            if '/' in target:
                parts = target.split('/')
                if len(parts) == 2 and parts[1].isdigit() and 0 <= int(parts[1]) <= 32:
                    try:
                        socket.inet_aton(parts[0])
                        return True, "cidr"
                    except socket.error:
                        pass
            
            return False, "invalid"
        except Exception as e:
            logger.error(f"Validation error: {str(e)}")
            return False, "error"

    def run_scan(self, target: str, scan_type: ScanType = ScanType.HYBRID) -> Dict:
        """Orchestrate scanning process"""
        valid, target_type = self.validate_target(target)
        if not valid:
            raise ValueError(f"Invalid target format: {target}")
            
        results = {
            "metadata": {
                "target": target,
                "scan_type": scan_type.value,
                "start_time": datetime.now(timezone.utc).isoformat(),
                "session_id": self.session_id
            },
            "results": {}
        }
        
        try:
            # Run scans based on type
            if scan_type in [ScanType.NMAP, ScanType.HYBRID]:
                nmap_results = self._run_advanced_nmap_scan(target)
                results["results"]["nmap"] = nmap_results
                
                # Enhanced vulnerability analysis
                if nmap_results.get("hosts"):
                    for host in nmap_results["hosts"]:
                        # This method now also handles AI analysis
                        self._enhanced_vulnerability_analysis(host) 
                
            if scan_type in [ScanType.OPENVAS, ScanType.HYBRID] and self.openvas_enabled:
                openvas_results = self._run_openvas_scan(target)
                results["results"]["openvas"] = openvas_results
                
            # Additional checks
            if scan_type == ScanType.HYBRID:
                self._run_supplemental_checks(target, results)
                
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
            raise
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}", exc_info=True)
            results["error"] = str(e)
            
        results["metadata"]["end_time"] = datetime.now(timezone.utc).isoformat()
        return results

    def _run_advanced_nmap_scan(self, target: str) -> Dict:
        """Perform comprehensive Nmap scan with vulnerability detection"""
        scan_args = "-sV -T4 --open --script vulners,vuln,http-vuln*,ssl-*"
        
        if os.geteuid() == 0:
            scan_args += " -O --traceroute"
            
        logger.info(f"Starting Nmap scan with args: {scan_args}")
        
        try:
            self.nmap_scanner.scan(hosts=target, arguments=scan_args)
            
            if not self.nmap_scanner.all_hosts():
                return {"error": "No hosts found"}
                
            results = {"hosts": []}
            
            for host in self.nmap_scanner.all_hosts():
                host_data = {
                    "ip": host,
                    "status": self.nmap_scanner[host].state(),
                    "ports": [],
                    "vulnerabilities": []
                }
                
                # Get hostnames if available
                hostnames = self.nmap_scanner[host].hostnames()
                if hostnames:
                    host_data["hostnames"] = [h["name"] for h in hostnames if h["name"]]
                
                # Get OS information if available
                if "osmatch" in self.nmap_scanner[host]:
                    host_data["os"] = self.nmap_scanner[host]["osmatch"][0]["name"]
                
                # Process ports and services
                for proto in self.nmap_scanner[host].all_protocols():
                    for port in self.nmap_scanner[host][proto].keys():
                        port_data = self.nmap_scanner[host][proto][port]
                        service_info = {
                            "port": port,
                            "protocol": proto,
                            "state": port_data["state"],
                            "service": port_data["name"],
                            "version": port_data.get("version", ""),
                            "product": port_data.get("product", ""),
                            "scripts": []
                        }
                        
                        # Process NSE script output
                        if "script" in port_data:
                            for script, output in port_data["script"].items():
                                script_data = {"name": script, "output": output}
                                
                                # Extract CVEs from script output
                                cves = self._extract_cves(output)
                                if cves:
                                    script_data["cves"] = cves
                                    
                                service_info["scripts"].append(script_data)
                        
                        host_data["ports"].append(service_info)
                        
                        # Check for known vulnerabilities
                        if port_data["name"] and port_data.get("product"):
                            vulns = self._check_service_vulnerabilities(
                                port_data["name"],
                                port_data["product"],
                                port_data.get("version", ""),
                                port
                            )
                            if vulns:
                                host_data["vulnerabilities"].extend(vulns)
                
                results["hosts"].append(host_data)
            
            return results
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {str(e)}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error during Nmap scan: {str(e)}")
            return {"error": str(e)}

    def _run_openvas_scan(self, target: str) -> Dict:
        """Run OpenVAS/GVM scan with result processing"""
        if not self.openvas_enabled:
            return {"error": "OpenVAS not configured"}
            
        logger.info("Starting OpenVAS scan...")
        
        try:
            # Start scan
            scan_result = self.openvas_client.start_scan([target])
            if not scan_result or 'task_id' not in scan_result:
                return {"error": "Failed to start OpenVAS scan"}
                
            task_id = scan_result['task_id']
            logger.info(f"OpenVAS scan started with ID: {task_id}")
            
            # Monitor scan progress
            while True:
                status = self.openvas_client.get_scan_status(task_id)
                if status.get('status') in ["Done", "Stopped", "Interrupted"]:
                    break
                time.sleep(30)
                
            # Get results
            results = self.openvas_client.get_results(task_id)
            if not results or results.get('status') != 'completed':
                return {"error": "No results from OpenVAS scan"}
                
            return results
            
        except Exception as e:
            logger.error(f"OpenVAS scan failed: {str(e)}")
            return {"error": str(e)}

    def _run_supplemental_checks(self, target: str, results: Dict):
        """Run additional security checks"""
        logger.info("Running supplemental checks...")
        
        # DNS checks
        dns_results = self._run_dns_checks(target)
        if dns_results:
            results["results"]["dns"] = dns_results
            
        # SSL/TLS checks (if HTTPS ports found)
        if any(port.get("service") == "https" 
               for host in results.get("results", {}).get("nmap", {}).get("hosts", [])
               for port in host.get("ports", [])):
            ssl_results = self._run_ssl_checks(target)
            if ssl_results:
                results["results"]["ssl"] = ssl_results
                
        # Shodan lookup if API key available
        if self.shodan_api_key:
            shodan_results = self._run_shodan_lookup(target)
            if shodan_results:
                results["results"]["shodan"] = shodan_results

    def _enhanced_vulnerability_analysis(self, host: Dict):
        """Perform deeper analysis on discovered services and get AI insights"""
        logger.info(f"Performing enhanced analysis for {host.get('ip')}")
        
        futures = []
        cve_vulns = [] # To store vulnerabilities with CVEs for exploit and AI check

        # Collect vulnerabilities that have CVEs for exploit and AI analysis
        for vuln_idx, vuln in enumerate(host.get("vulnerabilities", [])):
            if vuln.get("cve"):
                cve_vulns.append((vuln_idx, vuln))
                futures.append(
                    self.executor.submit(
                        self._check_exploit_availability,
                        vuln["cve"]
                    )
                )
        
        # Update with exploit info
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            original_idx = cve_vulns[i][0] # Get the original index
            host["vulnerabilities"][original_idx].exploit_available = future.result()

        # NEW: Get AI-generated analysis for each vulnerability
        if self.gemini_api_key and self.gemini_model: # Check if Gemini is enabled
            ai_futures = []
            for vuln_idx, vuln_obj in enumerate(host.get("vulnerabilities", [])):
                ai_futures.append(
                    self.executor.submit(
                        self._get_gemini_vulnerability_analysis,
                        vuln_obj,
                        host # Pass the host's overall information as context
                    )
                )
            
            for i, future in enumerate(concurrent.futures.as_completed(ai_futures)):
                ai_result = future.result()
                if ai_result:
                    host["vulnerabilities"][i].ai_analysis = ai_result["explanation"]
                else:
                    host["vulnerabilities"][i].ai_analysis = "AI analysis not available for this vulnerability."

    def _get_gemini_vulnerability_analysis(self, vulnerability: Vulnerability, host_info: Dict) -> Optional[Dict]:
        """
        Generates an explanation, impact, and recommendations for a given vulnerability
        using Gemini AI.
        """
        if not self.gemini_api_key or not self.gemini_model:
            logger.debug("Gemini AI is not enabled or initialized.")
            return None

        # Prepare context for Gemini
        host_ip = host_info.get("ip", "N/A")
        hostname = ", ".join(host_info.get("hostnames", [])) if host_info.get("hostnames") else "N/A"
        os_info = host_info.get("os", "Unknown OS")
        
        prompt = f"""
        You are a highly skilled cybersecurity analyst. Your task is to explain a detected vulnerability,
        its potential impact, and provide clear, actionable recommendations for remediation and
        general security best practices.

        Vulnerability Details:
        - CVE ID: {vulnerability.cve}
        - Description: {vulnerability.description}
        - CVSS Score: {vulnerability.cvss}
        - Severity: {vulnerability.severity.value}
        - Affected Port: {vulnerability.port if vulnerability.port else 'N/A'}
        - Affected Service: {vulnerability.service if vulnerability.service else 'N/A'}
        - Exploit Available: {'Yes' if vulnerability.exploit_available else 'No'}
        - References: {', '.join(vulnerability.references) if vulnerability.references else 'None'}

        Host Information:
        - IP Address: {host_ip}
        - Hostname: {hostname}
        - Operating System: {os_info}

        Please structure your response clearly with the following sections.
        Use markdown for formatting headings and bullet points.

        ### Vulnerability Explanation
        * What is this vulnerability in simple terms?
        * Why is it dangerous, and how could it be exploited?

        ### Potential Impact
        * What specific risks does this vulnerability pose to the system if exploited (e.g., data breach, unauthorized access, denial of service, remote code execution)?
        * Consider the context of the host and service.

        ### Specific Remediation Recommendations
        * Provide concrete, prioritized, and step-by-step instructions to fix or mitigate this particular vulnerability.
        * Include specific patches, configuration changes, or best practices relevant to the service/OS if applicable.

        ### General Security Best Practices
        * Suggest broader security practices that would help prevent similar vulnerabilities in the future and improve the overall system security posture.
        """

        try:
            logger.info(f"Querying Gemini for analysis of {vulnerability.cve}...")
            response = self.gemini_model.generate_content(prompt)
            if response.text:
                logger.info(f"Successfully received Gemini analysis for {vulnerability.cve}.")
                return {
                    "explanation": response.text # Gemini's full response
                }
            else:
                logger.warning(f"Gemini returned an empty response for {vulnerability.cve}.")
                return None
        except Exception as e:
            logger.error(f"Error querying Gemini for {vulnerability.cve}: {e}")
            return None

    def _check_service_vulnerabilities(self, service: str, product: str, version: str, port: int) -> List[Vulnerability]:
        """Check for known vulnerabilities in a service"""
        vulns = []
        
        # Check Vulners database
        if self.vulners_api_key:
            vulns.extend(self._query_vulners(service, product, version))
            
        # Check NVD database
        if self.nvd_api_key:
            vulns.extend(self._query_nvd(service, product, version))
            
        # Add port information to vulnerabilities
        for vuln in vulns:
            vuln.port = port
            
        return vulns

    def _query_vulners(self, service: str, product: str, version: str) -> List[Vulnerability]:
        """Query Vulners API for vulnerabilities"""
        try:
            query = f"{product} {version}"
            url = f"https://vulners.com/api/v3/search/lucene/?query={query}"
            headers = {"X-Api-Key": self.vulners_api_key} if self.vulners_api_key else {}
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulns = []
                
                for item in data.get("data", {}).get("search", []):
                    cve = item.get("cvelist", [""])[0]
                    if not cve.startswith("CVE-"):
                        continue
                        
                    cvss = float(item.get("cvss", {}).get("score", 0))
                    severity = self._cvss_to_severity(cvss)
                    
                    vulns.append(Vulnerability(
                        cve=cve,
                        description=item.get("description", ""),
                        cvss=cvss,
                        severity=severity,
                        references=item.get("references", [])
                    ))
                    
                return vulns
                
        except Exception as e:
            logger.warning(f"Vulners query failed: {str(e)}")
            
        return []

    def _query_nvd(self, service: str, product: str, version: str) -> List[Vulnerability]:
        """Query NVD API for vulnerabilities"""
        try:
            query = f"{product} {version}"
            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={query}"
            headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
            
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                vulns = []
                
                for item in data.get("result", {}).get("CVE_Items", []):
                    cve = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
                    if not cve:
                        continue
                        
                    # Get CVSS v3 score if available, fall back to v2
                    cvss_v3 = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")
                    cvss_v2 = item.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore")
                    cvss = float(cvss_v3) if cvss_v3 is not None else float(cvss_v2) if cvss_v2 is not None else 0.0
                    severity = self._cvss_to_severity(cvss)
                    
                    vulns.append(Vulnerability(
                        cve=cve,
                        description=item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", ""),
                        cvss=cvss,
                        severity=severity,
                        references=[ref.get("url") for ref in item.get("cve", {}).get("references", {}).get("reference_data", [])]
                    ))
                    
                return vulns
                
        except Exception as e:
            logger.warning(f"NVD query failed: {str(e)}")
            
        return []

    def _check_exploit_availability(self, cve: str) -> bool:
        """Check if exploit is available for a CVE"""
        try:
            # Check ExploitDB
            exploitdb_path = Path("/usr/share/exploitdb/exploits")
            if exploitdb_path.exists():
                grep_cmd = f"grep -r '{cve}' {exploitdb_path}"
                result = subprocess.run(grep_cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0 and cve in result.stdout:
                    return True
                    
            # Check Metasploit
            msf_path = Path("/usr/share/metasploit-framework/modules/exploits")
            if msf_path.exists():
                grep_cmd = f"grep -r '{cve}' {msf_path}"
                result = subprocess.run(grep_cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0 and cve in result.stdout:
                    return True
                    
            # Check Vulners for known exploits
            if self.vulners_api_key:
                url = f"https://vulners.com/api/v3/search/id/?id={cve}"
                headers = {"X-Api-Key": self.vulners_api_key}
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("data", {}).get("documents", {}).get(cve, {}).get("exploit"):
                        return True
                        
        except Exception as e:
            logger.warning(f"Exploit check failed for {cve}: {str(e)}")
            
        return False

    def _run_dns_checks(self, target: str) -> Dict:
        """Perform DNS reconnaissance"""
        try:
            import dns.resolver
            results = {}
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Basic resolution
            try:
                answers = resolver.resolve(target, 'A')
                results["A"] = [str(r) for r in answers]
            except:
                pass
                
            # MX records if domain
            if '.' in target and not target[0].isdigit():
                try:
                    answers = resolver.resolve(target, 'MX')
                    results["MX"] = [str(r) for r in answers]
                except:
                    pass
                    
            # TXT records
            try:
                answers = resolver.resolve(target, 'TXT')
                results["TXT"] = [str(r) for r in answers]
            except:
                pass
                
            return results if results else None
            
        except ImportError:
            logger.warning("dnspython not installed, skipping DNS checks")
            return None
        except Exception as e:
            logger.warning(f"DNS checks failed: {str(e)}")
            return None

    def _run_ssl_checks(self, target: str) -> Dict:
        """Perform SSL/TLS checks using testssl.sh"""
        try:
            testssl_path = shutil.which("testssl.sh")
            if not testssl_path:
                logger.warning("testssl.sh not found in PATH")
                return None
                
            output_file = Path(self.temp_dir) / f"ssl_{self.session_id}.json"
            cmd = f"{testssl_path} --jsonfile {output_file} --quiet {target}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning(f"testssl.sh failed: {result.stderr}")
                return None
                
            if not output_file.exists():
                return None
                
            with open(output_file, 'r') as f:
                data = json.load(f)
                
            # Process results into critical findings
            findings = []
            for item in data:
                if item.get("severity") in ["HIGH", "CRITICAL"]:
                    findings.append({
                        "id": item.get("id"),
                        "severity": item.get("severity"),
                        "finding": item.get("finding"),
                        "cve": item.get("cve")
                    })
                    
            return {"findings": findings} if findings else None
            
        except Exception as e:
            logger.warning(f"SSL checks failed: {str(e)}")
            return None

    def _run_shodan_lookup(self, target: str) -> Dict:
        """Query Shodan for internet exposure"""
        try:
            import shodan
            api = shodan.Shodan(self.shodan_api_key)
            
            # Remove port if present
            target = target.split(':')[0]
            
            # Check if it's an IP or hostname
            try:
                socket.inet_aton(target)
                result = api.host(target)
            except socket.error:
                result = api.search(f"hostname:{target}")
                
            # Process results
            processed = {
                "ports": [],
                "vulnerabilities": []
            }
            
            if isinstance(result, dict):  # IP lookup result
                for item in result.get("data", []):
                    port_info = {
                        "port": item.get("port"),
                        "product": item.get("product"),
                        "version": item.get("version"),
                        "banner": item.get("data")
                    }
                    processed["ports"].append(port_info)
                    
                for vuln in result.get("vulns", []):
                    processed["vulnerabilities"].append({
                        "id": vuln,
                        "verified": result["vulns"][vuln].get("verified", False)
                    })
                    
            elif isinstance(result, list):  # Hostname search result
                for host in result:
                    for item in host.get("data", []):
                        port_info = {
                            "port": item.get("port"),
                            "product": item.get("product"),
                            "version": item.get("version"),
                            "banner": item.get("data")
                        }
                        processed["ports"].append(port_info)
                        
            return processed if (processed["ports"] or processed["vulnerabilities"]) else None
            
        except ImportError:
            logger.warning("shodan not installed, skipping Shodan lookup")
            return None
        except Exception as e:
            logger.warning(f"Shodan lookup failed: {str(e)}")
            return None

    def _extract_cves(self, text: str) -> List[str]:
        """Extract CVE IDs from text"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return list(set(re.findall(cve_pattern, text, re.IGNORECASE)))

    def _normalize_severity(self, severity: str) -> Severity:
        """Normalize different severity formats"""
        severity = str(severity).upper()
        if severity in ["CRITICAL", "CRIT"]:
            return Severity.CRITICAL
        elif severity in ["HIGH", "SEVERE"]:
            return Severity.HIGH
        elif severity in ["MEDIUM", "MODERATE"]:
            return Severity.MEDIUM
        elif severity in ["LOW", "MINOR"]:
            return Severity.LOW
        else:
            return Severity.INFO

    def _cvss_to_severity(self, score: float) -> Severity:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0:
            return Severity.LOW
        return Severity.INFO

    def generate_report(self, results: Dict, format: str = "console") -> bool:
        """Generate report in specified format"""
        if not results:
            return False
            
        try:
            if format == "console":
                self._print_console_report(results)
            elif format == "json":
                with open(f"scan_report_{self.session_id}.json", 'w') as f:
                    json.dump(results, f, indent=2)
            elif format == "pdf":
                self._generate_pdf_report(results)
            else:
                logger.error(f"Unsupported report format: {format}")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            return False

    def _print_console_report(self, results: Dict):
        """Print formatted report to console"""
        print("\n=== VULNERABILITY SCAN REPORT ===")
        print(f"\nScan ID: {results['metadata']['session_id']}")
        print(f"Target: {results['metadata']['target']}")
        print(f"Started: {results['metadata']['start_time']}")
        print(f"Completed: {results['metadata']['end_time']}")
        
        # Nmap results
        if "nmap" in results["results"]:
            print("\n--- Nmap Results ---")
            for host in results["results"]["nmap"].get("hosts", []):
                print(f"\nHost: {host['ip']}")
                if "hostnames" in host:
                    print(f"Hostnames: {', '.join(host['hostnames'])}")
                if "os" in host:
                    print(f"OS: {host['os']}")
                    
                print("\nOpen Ports:")
                for port in host.get("ports", []):
                    print(f"  {port['port']}/{port['protocol']}: {port['service']} {port.get('version', '')}")
                    for script in port.get("scripts", []):
                        print(f"    {script['name']}:")
                        for line in script['output'].split('\n'):
                            print(f"      {line}")
                            
                if host.get("vulnerabilities"):
                    print("\nVulnerabilities:")
                    for vuln in host["vulnerabilities"]:
                        # Support both dict and dataclass object
                        cve = getattr(vuln, "cve", vuln.get("cve")) if isinstance(vuln, dict) else vuln.cve
                        severity = getattr(vuln, "severity", vuln.get("severity")) if isinstance(vuln, dict) else vuln.severity
                        cvss = getattr(vuln, "cvss", vuln.get("cvss")) if isinstance(vuln, dict) else vuln.cvss
                        description = getattr(vuln, "description", vuln.get("description")) if isinstance(vuln, dict) else vuln.description
                        exploit_available = getattr(vuln, "exploit_available", vuln.get("exploit_available", False)) if isinstance(vuln, dict) else vuln.exploit_available
                        ai_analysis = getattr(vuln, "ai_analysis", vuln.get("ai_analysis")) if isinstance(vuln, dict) else vuln.ai_analysis

                        print(f"  {cve} ({severity.value if hasattr(severity, 'value') else severity} - CVSS: {cvss})")
                        if exploit_available:
                            print("    [EXPLOIT AVAILABLE]")
                        print(f"    Description: {description}")
                        if ai_analysis:
                            print("\n    AI-Generated Analysis & Recommendations:")
                            for line in ai_analysis.splitlines():
                                print(f"    {line.strip()}")
                        print("-" * 40)
                        
        # OpenVAS results (No changes here, as AI integration focuses on Nmap-detected vulns for this version)
        if "openvas" in results["results"]:
            print("\n--- OpenVAS Results ---")
            ov_results = results["results"]["openvas"]
            print(f"\nScan ID: {ov_results.get('scan_id')}")
            print(f"Findings: {ov_results.get('summary', {}).get('total', 0)}")
            print(f"Critical: {ov_results.get('summary', {}).get('critical', 0)}")
            print(f"High: {ov_results.get('summary', {}).get('high', 0)}")
            print(f"Medium: {ov_results.get('summary', {}).get('medium', 0)}")
            print(f"Low: {ov_results.get('summary', {}).get('low', 0)}")
            
            for finding in ov_results.get("findings", []):
                print(f"\n[{finding['severity']}] {finding['name']}")
                print(f"Port: {finding.get('port', 'N/A')}")
                if finding.get("cves"):
                    print(f"CVEs: {', '.join(finding['cves'])}")
                print(f"\nDescription:\n{finding['description']}")
                
        # Supplemental results (No changes here)
        if "ssl" in results["results"]:
            print("\n--- SSL/TLS Findings ---")
            for finding in results["results"]["ssl"].get("findings", []):
                print(f"\n[{finding['severity']}] {finding['id']}")
                if finding.get("cve"):
                    print(f"CVE: {finding['cve']}")
                print(f"Finding: {finding['finding']}")
                
        print("\n=== END OF REPORT ===")

    def _generate_pdf_report(self, results: Dict):
        """Generate a detailed PDF report using FPDF2"""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", size=12)
        
        # Header
        pdf.cell(200, 10, text="VULNERABILITY SCAN REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        pdf.set_font("helvetica", size=10)
        pdf.cell(200, 5, text=f"Scan ID: {results['metadata']['session_id']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(200, 5, text=f"Target: {results['metadata']['target']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(200, 5, text=f"Scan Period: {results['metadata']['start_time']} to {results['metadata']['end_time']}", 
               new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(10)
        
        # Nmap results
        if "nmap" in results["results"]:
            pdf.set_font("helvetica", style="B", size=12)
            pdf.cell(200, 10, text="Nmap Scan Results", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=10)
            
            for host in results["results"]["nmap"].get("hosts", []):
                pdf.set_font(style="B")
                pdf.cell(200, 8, text=f"Host: {host['ip']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font(style="")
                
                if "hostnames" in host:
                    pdf.cell(200, 8, text=f"Hostnames: {', '.join(host['hostnames'])}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                if "os" in host:
                    pdf.cell(200, 8, text=f"OS: {host['os']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    
                pdf.cell(200, 8, text="Open Ports:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                for port in host.get("ports", []):
                    pdf.cell(200, 8, text=f"  {port['port']}/{port['protocol']}: {port['service']} {port.get('version', '')}", 
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    # NSE Scripts
                    for script in port.get("scripts", []):
                        pdf.set_font(style="I")
                        pdf.cell(200, 8, text=f"    Script: {script['name']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                        pdf.set_font(style="")
                        for line in script['output'].split('\n'):
                            pdf.multi_cell(0, 6, text=f"      {line}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                        if script.get("cves"):
                            pdf.cell(200, 8, text=f"      CVEs: {', '.join(script['cves'])}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(1)
                # Vulnerabilities
                if host.get("vulnerabilities"):
                    pdf.set_font("helvetica", style="B", size=11)
                    pdf.cell(200, 8, text="Vulnerabilities:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font("helvetica", size=10)
                    
                    for vuln in host["vulnerabilities"]:
                        cve = getattr(vuln, "cve", vuln.get("cve")) if isinstance(vuln, dict) else vuln.cve
                        severity = getattr(vuln, "severity", vuln.get("severity")) if isinstance(vuln, dict) else vuln.severity
                        cvss = getattr(vuln, "cvss", vuln.get("cvss")) if isinstance(vuln, dict) else vuln.cvss
                        description = getattr(vuln, "description", vuln.get("description")) if isinstance(vuln, dict) else vuln.description
                        exploit_available = getattr(vuln, "exploit_available", vuln.get("exploit_available", False)) if isinstance(vuln, dict) else vuln.exploit_available
                        ai_analysis = getattr(vuln, "ai_analysis", vuln.get("ai_analysis")) if isinstance(vuln, dict) else vuln.ai_analysis

                        pdf.set_font(style="B")
                        pdf.cell(200, 7, text=f"  CVE: {cve} ({severity.value if hasattr(severity, 'value') else severity} - CVSS: {cvss})", 
                               new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                        pdf.set_font(style="")
                        if exploit_available:
                            pdf.cell(200, 6, text="    [EXPLOIT AVAILABLE]", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True, border=1, align='C')
                        pdf.multi_cell(0, 6, text=f"    Description: {description}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                        if ai_analysis:
                            pdf.set_font("helvetica", style="I", size=9)
                            pdf.multi_cell(0, 5, text="    AI-Generated Analysis & Recommendations:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                            pdf.set_font("helvetica", size=9)
                            for line in ai_analysis.splitlines():
                                if line.strip():
                                    pdf.multi_cell(0, 4, text=f"    {line.strip()}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                            pdf.ln(2)
                        pdf.ln(5)
        
        # OpenVAS results (No changes here, as AI integration focuses on Nmap-detected vulns for this version)
        if "openvas" in results["results"]:
            pdf.set_font("helvetica", style="B", size=12)
            pdf.cell(200, 10, text="OpenVAS Scan Results", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=10)

            ov_results = results["results"]["openvas"]
            pdf.cell(200, 6, text=f"Scan ID: {ov_results.get('scan_id', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.cell(200, 6, text=f"Total Findings: {ov_results.get('summary', {}).get('total', 0)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.cell(200, 6, text=f"Critical: {ov_results.get('summary', {}).get('critical', 0)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.cell(200, 6, text=f"High: {ov_results.get('summary', {}).get('high', 0)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.cell(200, 6, text=f"Medium: {ov_results.get('summary', {}).get('medium', 0)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.cell(200, 6, text=f"Low: {ov_results.get('summary', {}).get('low', 0)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(5)
            
            for finding in ov_results.get("findings", []):
                pdf.set_font(style="B")
                pdf.cell(200, 7, text=f"[{finding['severity']}] {finding['name']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font(style="")
                pdf.cell(200, 6, text=f"Port: {finding.get('port', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                if finding.get("cves"):
                    pdf.cell(200, 6, text=f"CVEs: {', '.join(finding['cves'])}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.multi_cell(0, 6, text=f"Description:\n{finding['description']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.ln(5)

        # SSL/TLS Findings (No changes here)
        if "ssl" in results["results"] and results["results"]["ssl"] and results["results"]["ssl"].get("findings"):
            pdf.set_font("helvetica", style="B", size=12)
            pdf.cell(200, 10, text="SSL/TLS Findings", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=10)
            for finding in results["results"]["ssl"].get("findings", []):
                pdf.set_font(style="B")
                pdf.cell(200, 7, text=f"[{finding['severity']}] {finding['id']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font(style="")
                if finding.get("cve"):
                    pdf.cell(200, 6, text=f"CVE: {finding['cve']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.multi_cell(0, 6, text=f"Finding: {finding['finding']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.ln(5)

        # Shodan Results (No changes here)
        if "shodan" in results["results"] and results["results"]["shodan"]:
            pdf.set_font("helvetica", style="B", size=12)
            pdf.cell(200, 10, text="Shodan Internet Exposure", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=10)
            shodan_res = results["results"]["shodan"]
            if shodan_res.get("ports"):
                pdf.cell(200, 7, text="Exposed Ports:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                for p in shodan_res["ports"]:
                    pdf.multi_cell(0, 6, text=f"  Port: {p.get('port')}, Product: {p.get('product', 'N/A')}, Version: {p.get('version', 'N/A')}", 
                                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if shodan_res.get("vulnerabilities"):
                pdf.cell(200, 7, text="Associated Vulnerabilities (Shodan):", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                for v in shodan_res["vulnerabilities"]:
                    pdf.multi_cell(0, 6, text=f"  ID: {v.get('id')}, Verified: {v.get('verified')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(5)

        # DNS Results (No changes here)
        if "dns" in results["results"] and results["results"]["dns"]:
            pdf.set_font("helvetica", style="B", size=12)
            pdf.cell(200, 10, text="DNS Records", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=10)
            for record_type, records in results["results"]["dns"].items():
                pdf.multi_cell(0, 6, text=f"  {record_type}: {', '.join(records)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(5)

        output_filename = f"scan_report_{self.session_id}.pdf"
        pdf.output(output_filename)
        logger.info(f"PDF report generated: {output_filename}")

# Main execution block
if __name__ == "__main__":
    # Banner
    print("=" * 60)
    print("        ADVANCED VULNERABILITY SCANNER".center(60))
    print("        by K.Musomi".center(60))
    print("=" * 60)
    print()

    # Prompt for target
    target_input = input("Enter target IP or hostname: ").strip()
    while not target_input:
        target_input = input("Target cannot be empty. Enter target IP or hostname: ").strip()

    print("\n" + "-" * 60)
    print("Scan Types:")
    print("  nmap    - Fast service & vulnerability scan")
    print("  openvas - Deep authenticated vulnerability scan (if configured)")
    print("  hybrid  - Both Nmap and OpenVAS (recommended)")
    print("-" * 60)
    scan_type_str = input("Scan type? (nmap/openvas/hybrid) [hybrid]: ").strip().lower()
    if scan_type_str not in ("nmap", "openvas", "hybrid", ""):
        print("Invalid scan type. Defaulting to 'hybrid'.")
        scan_type_str = "hybrid"
    if not scan_type_str:
        scan_type_str = "hybrid"

    print("\n" + "-" * 60)
    print("Report Formats:")
    print("  console - Print results to terminal")
    print("  json    - Save results as JSON")
    print("  pdf     - Generate a detailed PDF report")
    print("-" * 60)
    report_format = input("Report format? (console/json/pdf) [console]: ").strip().lower()
    if report_format not in ("console", "json", "pdf", ""):
        print("Invalid report format. Defaulting to 'console'.")
        report_format = "console"
    if not report_format:
        report_format = "console"

    try:
        scan_type = ScanType[scan_type_str.upper()]
    except KeyError:
        logger.error(f"Invalid scan type: {scan_type_str}. Supported types are: nmap, openvas, hybrid.")
        sys.exit(1)

    # Summary banner
    print("\n" + "=" * 60)
    print("SCAN SUMMARY".center(60))
    print("=" * 60)
    print(f"Target       : {target_input}")
    print(f"Scan Type    : {scan_type.value}")
    print(f"Report Format: {report_format}")
    print("=" * 60 + "\n")

    scanner = AdvancedVulnerabilityScanner()

    # Initial validation and cleanup of target input for logging/display
    parsed_target = target_input
    if target_input.startswith(('http://', 'https://')):
        parsed_target = urlparse(target_input).netloc.split(':')[0]

    logger.info(f"Starting scan for target: {parsed_target} with type: {scan_type.value}, report format: {report_format}")

    try:
        scan_results = scanner.run_scan(target_input, scan_type)
        if scan_results and not scan_results.get("error"):
            logger.info("Scan completed successfully. Generating report...")
            scanner.generate_report(scan_results, report_format)
        else:
            logger.error(f"Scan failed or returned no results: {scan_results.get('error', 'Unknown error')}")
            sys.exit(1)
    except ValueError as ve:
        logger.error(f"Configuration or validation error: {ve}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unhandled error occurred during scan execution: {e}", exc_info=True)
        sys.exit(1)
