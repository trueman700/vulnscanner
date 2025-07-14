from typing import Dict, Optional, List, Tuple
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.errors import GvmError
from gvm.connections import UnixSocketConnection, TLSConnection
import logging
import time
import ipaddress
import socket
from datetime import datetime
from lxml import etree # Ensure lxml is installed: pip install lxml
import os

logger = logging.getLogger(__name__)

class OpenVASClient:
    def __init__(self, 
                 host: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 timeout: int = 60,
                 debug: bool = False):
        """Modern OpenVAS/GVM client with automatic connection handling"""
        
        self.host = host or os.getenv('OPENVAS_HOST', 'localhost')
        self.username = username or os.getenv('OPENVAS_USER', 'admin')
        self.password = password or os.getenv('OPENVAS_PASS', 'admin')
        self.timeout = timeout
        self.debug = debug
        
        # Default configurations (modern GVM for GVM 22.7.x)
        # These are commonly used UUIDs, but can vary slightly depending on your GVM setup.
        # It's good practice to fetch these dynamically if possible (as shown in get_configurations)
        # and allow overrides.
        self.default_configs = {
            'scan_config': 'daba56c8-73ec-11df-a475-002264764cea',  # Full and fast
            'port_list': '4a4717fe-57d2-11e1-9ae8-406186ea4fc5',    # All IANA assigned TCP
                                                                    # (Common UUID for GVM 22.x)
                                                                    # Original was '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'
            'scanner': '08b69003-5fc2-4037-a479-93b440211c73',       # OpenVAS Default
            'report_format_xml': 'a994b278-1f62-11e1-96ac-406186ea4fc5', # XML report format
            'report_format_html': '6c93693e-257a-11e7-91a0-28d24461215b' # HTML report format
        }
        
        self.connection = None # This will store the active connection object
        self.gmp = None        # This will store the active GMP session
        self.transform = EtreeTransform()

        # Establish connection during initialization
        try:
            self._establish_and_authenticate_gmp()
            logger.info("OpenVAS client initialized and connected successfully.")
        except GvmError as e:
            logger.error(f"OpenVAS client initialization failed: {e}")
            raise # Re-raise to indicate a critical failure

    def _establish_and_authenticate_gmp(self):
        """
        Establishes a connection and authenticates a GMP session.
        This method will try various connection methods until one succeeds.
        If successful, it sets self.connection and self.gmp.
        """
        connection_methods = [
            ('Unix Socket (Default)', lambda: UnixSocketConnection(path='/run/gvm/gvmd.sock')),
            ('Unix Socket (Legacy)', lambda: UnixSocketConnection(path='/run/gvmd/gvmd.sock')),
            ('TLS Localhost', lambda: TLSConnection(hostname='localhost', port=9390, timeout=self.timeout)),
            ('TLS Custom', lambda: TLSConnection(hostname=self.host, port=9390, timeout=self.timeout))
        ]
        
        for name, connector in connection_methods:
            try:
                if self.debug:
                    logger.info(f"Attempting {name} connection...")
                
                conn = connector()
                conn.connect() # Explicitly connect
                
                gmp = Gmp(conn, transform=self.transform)
                gmp.authenticate(self.username, self.password)
                
                self.connection = conn
                self.gmp = gmp
                if self.debug:
                    logger.info(f"Successfully connected and authenticated via {name}")
                return
                    
            except Exception as e:
                if self.debug:
                    logger.warning(f"{name} failed: {str(e)}")
                # Ensure connection is closed if it failed mid-way
                try:
                    if 'conn' in locals() and conn.is_connected():
                        conn.close()
                except Exception:
                    pass
                continue # Try next connection method
                
        raise GvmError("Could not establish connection or authenticate using any method. "
                       "Please check GVM services, socket paths, or TLS configuration.")

    def _ensure_authenticated_gmp(self) -> Gmp:
        """
        Ensures that self.gmp is an active, authenticated GMP session.
        If the connection is lost, it attempts to re-establish it.
        """
        if not self.gmp or not self.connection.is_connected():
            logger.info("Re-establishing OpenVAS connection...")
            try:
                # Close potentially stale connection first
                if self.connection and self.connection.is_connected():
                    self.connection.close()
                self._establish_and_authenticate_gmp()
            except GvmError as e:
                logger.error(f"Failed to re-establish OpenVAS connection: {e}")
                raise
        return self.gmp


    def validate_targets(self, targets: List[str]) -> Tuple[List[str], List[str]]:
        """Validate multiple targets, return (valid, invalid)"""
        valid, invalid = [], []
        for target in targets:
            try:
                if self._validate_target(target):
                    valid.append(target)
                else:
                    invalid.append(target)
            except Exception as e:
                logger.warning(f"Validation error for {target}: {str(e)}")
                invalid.append(target)
        return valid, invalid

    def _validate_target(self, target: str) -> bool:
        """Validate single target format (IP, CIDR, hostname)"""
        try:
            # Check for CIDR or IP
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
            else:
                ipaddress.ip_address(target)
            return True
        except ValueError:
            # If not an IP/CIDR, try resolving as a hostname
            try:
                socket.gethostbyname(target)
                return True
            except socket.error:
                return False

    def start_scan(self, targets: List[str], 
                  config_id: Optional[str] = None,
                  port_list_id: Optional[str] = None) -> Optional[Dict]:
        """Start scan with hybrid target support"""
        valid_targets, invalid_targets = self.validate_targets(targets)
        if not valid_targets:
            logger.error("No valid targets provided for scan.")
            return None

        try:
            gmp = self._ensure_authenticated_gmp()

            # Create target
            # For GVM 22.x, 'hosts' argument needs to be a comma-separated string, not a list.
            target_id = self._create_target(
                gmp, 
                ",".join(valid_targets), # Pass as comma-separated string
                port_list_id or self.default_configs['port_list']
            )
            
            # Create and start task
            task_id = self._create_task(
                gmp,
                target_id,
                config_id or self.default_configs['scan_config']
            )
            
            return {
                'task_id': task_id,
                'target_id': target_id,
                'valid_targets': valid_targets,
                'invalid_targets': invalid_targets,
                'start_time': datetime.now().isoformat()
            }
                
        except Exception as e:
            logger.error(f"OpenVAS scan setup failed: {str(e)}", exc_info=self.debug)
            return None

    def _create_target(self, gmp: Gmp, hosts_str: str, port_list_id: str) -> str:
        """Create scan target resource (hosts_str should be comma-separated)"""
        try:
            logger.info(f"Creating OpenVAS target for hosts: {hosts_str}")
            response = gmp.create_target(
                name=f"Scan Target {datetime.now().strftime('%Y%m%d-%H%M%S')}",
                hosts=hosts_str, # This is now a string
                port_list_id=port_list_id,
                alive_test="ICMP, TCP-ACK Service & ARP Ping"
            )
            target_id = response.xpath('/create_target_response/@id')[0] # Corrected xpath
            logger.info(f"OpenVAS target created with ID: {target_id}")
            return target_id
        except (GvmError, IndexError) as e:
            logger.error(f"OpenVAS target creation failed: {str(e)}", exc_info=True)
            raise GvmError(f"Target creation failed: {e}")

    def _create_task(self, gmp: Gmp, target_id: str, config_id: str) -> str:
        """Create scan task and start it"""
        try:
            task_name = f"Scan Task {datetime.now().strftime('%Y%m%d-%H%M%S')}"
            logger.info(f"Creating OpenVAS task '{task_name}' for target ID: {target_id}")
            response = gmp.create_task(
                name=task_name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=self.default_configs['scanner']
            )
            task_id = response.xpath('/create_task_response/@id')[0] # Corrected xpath
            logger.info(f"OpenVAS task created with ID: {task_id}")
            
            # Start the task
            logger.info(f"Starting OpenVAS task ID: {task_id}")
            start_resp = gmp.start_task(task_id)
            # GVM 22.x start_task response might not always have an explicit status attribute
            # Check for presence of the 'report_id' or success indication
            if not start_resp.xpath('/start_task_response/report_id'):
                 # More robust check for success. If report_id is not immediately available,
                 # it implies the task is now running and will generate one.
                logger.warning(f"Task {task_id} started, but no immediate report_id in response. Status will be 'Requested' or 'Running'.")
                pass # Task successfully requested to start
                
            return task_id
            
        except (GvmError, IndexError) as e:
            logger.error(f"OpenVAS task creation or start failed: {str(e)}", exc_info=True)
            raise GvmError(f"Task creation/start failed: {e}")

    def get_scan_status(self, task_id: str) -> Dict:
        """Get current scan status"""
        try:
            gmp = self._ensure_authenticated_gmp()
            task_response = gmp.get_task(task_id)
            
            # Using findtext for simplicity and robustness
            status = task_response.findtext('.//task/status')
            progress = task_response.findtext('.//task/progress')
            
            return {
                'task_id': task_id,
                'status': status,
                'progress': int(progress) if progress else 0, # Ensure progress is int
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"OpenVAS status check failed for task {task_id}: {str(e)}", exc_info=self.debug)
            return {
                'task_id': task_id,
                'status': 'error',
                'error': str(e)
            }

    def get_results(self, task_id: str, min_severity: float = 4.0) -> Dict: # Changed default to 4.0 (Medium)
        """Retrieve scan results with severity filtering"""
        try:
            gmp = self._ensure_authenticated_gmp()
            task_response = gmp.get_task(task_id)
            
            task_status = task_response.findtext('.//task/status')
            if task_status != 'Done':
                logger.info(f"Task {task_id} is not yet 'Done'. Current status: {task_status}")
                return {
                    'status': 'incomplete',
                    'task_id': task_id,
                    'current_status': task_status
                }
            
            # Get the report_id from the task response
            report_id = task_response.xpath('//task/last_report/report/@id')
            if not report_id:
                # Sometimes there's no last_report immediately if task just finished
                # We might need to wait a tiny bit or retry
                logger.warning(f"No report ID found for task {task_id} even though status is 'Done'. Retrying in 5s...")
                time.sleep(5)
                task_response = gmp.get_task(task_id)
                report_id = task_response.xpath('//task/last_report/report/@id')
                if not report_id:
                    logger.error(f"Still no report ID for task {task_id} after retry.")
                    return {
                        'status': 'error',
                        'task_id': task_id,
                        'error': 'No report ID found for completed task.'
                    }

            report_id = report_id[0] # Get the first ID
            logger.info(f"Retrieving report {report_id} for task {task_id}")

            # Filter string for get_report is usually based on severity and QOD (Quality of Detection)
            # `min_qod=70` is a good default. `min_severity` applies a filter for reported items.
            filter_str = f"apply_overrides=1 levels=hmlg min_qod=70 severity>={min_severity}"
            
            report = gmp.get_report(
                report_id,
                report_format_id=self.default_configs['report_format_xml'], # Use XML format
                filter_string=filter_str
            )
            
            findings_data = self._parse_report(report)
            
            return {
                'status': 'completed',
                'task_id': task_id,
                'report_id': report_id,
                'summary': self._generate_summary(findings_data),
                'findings': findings_data['parsed_findings'], # Return the list of parsed findings
                'timestamp': datetime.now().isoformat()
            }
                
        except Exception as e:
            logger.error(f"OpenVAS result retrieval failed for task {task_id}: {str(e)}", exc_info=self.debug)
            return {
                'status': 'error',
                'task_id': task_id,
                'error': str(e)
            }

    def _parse_report(self, report_element: etree.Element) -> Dict:
        """Parse XML report into structured data, directly from etree.Element"""
        parsed_findings = []
        summary_stats = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
            'total': 0, 'hosts': set(), 'ports': set()
        }
        
        # Correct path for results
        results_path = '//report/results/result' 
        for result in report_element.xpath(results_path):
            try:
                # Use findtext for direct string extraction, handle None
                severity_str = result.findtext('severity')
                severity = float(severity_str) if severity_str else 0.0
                if severity < 0: # Ensure non-negative for info levels
                    severity = 0

                threat = result.findtext('threat')
                # Map GVM threat levels to custom Severity enum (if desired, currently string)
                # You might want to map these to your Severity Enum like Severity.CRITICAL
                # For now, just using the string.
                # threat_level = self._normalize_severity(threat) if threat else Severity.INFO

                finding_id = result.xpath('@id')[0] if result.xpath('@id') else 'N/A'
                name = result.findtext('name')
                description = result.findtext('description')
                host = result.findtext('host')
                # Port can be complex, e.g., 'general/tcp', '80/tcp'. Extract just the port number.
                port_raw = result.findtext('port')
                port_num = port_raw.split('/')[0] if port_raw and '/' in port_raw else port_raw if port_raw else 'N/A'
                
                qod_value = result.findtext('qod/value')
                qod = int(qod_value) if qod_value else 0

                nvt_oid = result.xpath('nvt/@oid')[0] if result.xpath('nvt/@oid') else 'N/A'
                nvt_family = result.findtext('nvt/family')
                creation_time = result.findtext('creation_time')

                finding = {
                    'id': finding_id,
                    'name': name,
                    'description': description,
                    'host': host,
                    'port': port_num, # Store just the port number
                    'severity': severity, # Numerical severity
                    'severity_text': self._cvss_to_severity(severity).value, # Convert to your Severity Enum text
                    'qod': qod,
                    'nvt': {
                        'oid': nvt_oid,
                        'family': nvt_family
                    },
                    'threat': threat, # GVM's threat level (e.g., 'Log', 'Low', 'Medium', 'High', 'Critical')
                    'timestamp': creation_time
                }
                
                parsed_findings.append(finding)
                
                # Update summary stats
                summary_stats['total'] += 1
                if severity >= 9.0:
                    summary_stats['critical'] += 1
                elif severity >= 7.0:
                    summary_stats['high'] += 1
                elif severity >= 4.0:
                    summary_stats['medium'] += 1
                elif severity > 0:
                    summary_stats['low'] += 1
                else:
                    summary_stats['info'] += 1
                
                summary_stats['hosts'].add(host)
                if port_num != 'N/A':
                    summary_stats['ports'].add(port_num)
                    
            except Exception as e:
                logger.warning(f"Failed to parse a result entry in OpenVAS report: {str(e)}", exc_info=True)
                continue
                
        summary_stats['hosts'] = list(summary_stats['hosts'])
        summary_stats['ports'] = list(summary_stats['ports'])

        return {'parsed_findings': parsed_findings, 'summary_stats': summary_stats}


    def _generate_summary(self, findings_data: Dict) -> Dict:
        """Generate comprehensive scan summary from parsed findings data"""
        summary_stats = findings_data['summary_stats']
        total = summary_stats['total']

        return {
            'total_vulnerabilities': total,
            'affected_hosts': len(summary_stats['hosts']),
            'affected_ports': len(summary_stats['ports']),
            'critical': summary_stats['critical'],
            'high': summary_stats['high'],
            'medium': summary_stats['medium'],
            'low': summary_stats['low'],
            'info': summary_stats['info'],
            'severity_distribution': {
                'critical': self._percentage(summary_stats['critical'], total),
                'high': self._percentage(summary_stats['high'], total),
                'medium': self._percentage(summary_stats['medium'], total),
                'low': self._percentage(summary_stats['low'], total),
                'info': self._percentage(summary_stats['info'], total)
            }
        }

    def _percentage(self, part: int, whole: int) -> float:
        """Calculate percentage"""
        return round((part / whole) * 100, 2) if whole > 0 else 0.0

    # Added this helper for consistency with scanner.py Severity enum
    def _cvss_to_severity(self, score: float):
        """Convert CVSS score to severity level for text representation"""
        # This mirrors the logic in scanner.py to get consistent severity text
        from enum import Enum # Local import to avoid circular dependency
        class Severity(Enum):
            CRITICAL = "Critical"
            HIGH = "High"
            MEDIUM = "Medium"
            LOW = "Low"
            INFO = "Informational"

        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0:
            return Severity.LOW
        return Severity.INFO

    def cleanup(self, task_id: str, target_id: str) -> bool:
        """Clean up scan resources"""
        try:
            gmp = self._ensure_authenticated_gmp()
            logger.info(f"Deleting OpenVAS task {task_id}")
            gmp.delete_task(task_id, ultimate=True) # ultimate=True to delete associated report and results
            logger.info(f"Deleting OpenVAS target {target_id}")
            gmp.delete_target(target_id, ultimate=True)
            return True
        except Exception as e:
            logger.error(f"OpenVAS cleanup failed for task {task_id}, target {target_id}: {str(e)}", exc_info=self.debug)
            return False

    def get_configurations(self) -> Dict:
        """Get available scan configurations"""
        try:
            gmp = self._ensure_authenticated_gmp()
            return {
                'scan_configs': self._get_scan_configs(gmp),
                'port_lists': self._get_port_lists(gmp),
                'scanners': self._get_scanners(gmp)
            }
        except Exception as e:
            logger.error(f"OpenVAS configuration retrieval failed: {str(e)}", exc_info=self.debug)
            return {}

    def _get_scan_configs(self, gmp: Gmp) -> List[Dict]:
        """Retrieve available scan configs"""
        configs = gmp.get_scan_configs()
        return [{
            'id': c.xpath('@id')[0],
            'name': c.xpath('name/text()')[0],
            'description': c.xpath('comment/text()')[0] if c.xpath('comment/text()') else ''
        } for c in configs.xpath('//config')]

    def _get_port_lists(self, gmp: Gmp) -> List[Dict]:
        """Retrieve available port lists"""
        port_lists = gmp.get_port_lists()
        return [{
            'id': p.xpath('@id')[0],
            'name': p.xpath('name/text()')[0],
            'description': p.xpath('comment/text()')[0] if p.xpath('comment/text()') else ''
        } for p in port_lists.xpath('//port_list')]

    def _get_scanners(self, gmp: Gmp) -> List[Dict]:
        """Retrieve available scanners"""
        scanners = gmp.get_scanners()
        return [{
            'id': s.xpath('@id')[0],
            'name': s.xpath('name/text()')[0],
            'type': s.xpath('type/text()')[0]
        } for s in scanners.xpath('//scanner')]