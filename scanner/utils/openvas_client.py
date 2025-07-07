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
from lxml import etree
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
        
        # Default configurations (modern GVM)
        self.default_configs = {
            'scan_config': 'daba56c8-73ec-11df-a475-002264764cea',  # Full and fast
            'port_list': '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',    # All IANA assigned TCP
            'scanner': '08b69003-5fc2-4037-a479-93b440211c73'       # OpenVAS Default
        }
        
        # Connection sequence - tries socket first, then TLS
        self.connection = self._establish_connection()
        self.transform = EtreeTransform()

    def _establish_connection(self):
        """Try all possible connection methods"""
        connection_methods = [
            ('Unix Socket (Default)', lambda: UnixSocketConnection(
                path='/run/gvm/gvmd.sock')),
            ('Unix Socket (Legacy)', lambda: UnixSocketConnection(
                path='/run/gvmd/gvmd.sock')),
            ('TLS Localhost', lambda: TLSConnection(
                hostname='localhost', port=9390, timeout=self.timeout)),
            ('TLS Custom', lambda: TLSConnection(
                hostname=self.host, port=9390, timeout=self.timeout))
        ]
        
        for name, connector in connection_methods:
            try:
                if self.debug:
                    logger.info(f"Attempting {name} connection...")
                
                conn = connector()
                with Gmp(conn) as gmp:
                    gmp.authenticate(self.username, self.password)
                    if self.debug:
                        logger.info(f"Successfully connected via {name}")
                    return conn
                    
            except Exception as e:
                if self.debug:
                    logger.warning(f"{name} failed: {str(e)}")
                continue
                
        raise GvmError("Could not establish connection using any method")

    def _get_gmp_connection(self) -> Gmp:
        """Get authenticated GMP connection"""
        try:
            gmp = Gmp(self.connection, transform=self.transform)
            gmp.authenticate(self.username, self.password)
            return gmp
        except Exception as e:
            logger.error(f"Connection failed: {str(e)}")
            raise

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
        """Validate single target format"""
        try:
            if '/' in target or '-' in target:
                ipaddress.ip_network(target, strict=False)
            else:
                ipaddress.ip_address(target) or socket.gethostbyname(target)
            return True
        except (ValueError, socket.error):
            return False

    def start_scan(self, targets: List[str], 
                  config_id: Optional[str] = None,
                  port_list_id: Optional[str] = None) -> Optional[Dict]:
        """Start scan with hybrid target support"""
        valid_targets, invalid_targets = self.validate_targets(targets)
        if not valid_targets:
            logger.error("No valid targets provided")
            return None

        try:
            with self._get_gmp_connection() as gmp:
                # Create target
                target_id = self._create_target(
                    gmp, 
                    valid_targets,
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
            logger.error(f"Scan setup failed: {str(e)}")
            return None

    def _create_target(self, gmp: Gmp, hosts: List[str], port_list_id: str) -> str:
        """Create scan target resource"""
        try:
            response = gmp.create_target(
                name=f"Scan {datetime.now().strftime('%Y%m%d-%H%M%S')}",
                hosts=hosts,
                port_list_id=port_list_id,
                alive_test="ICMP, TCP-ACK Service & ARP Ping"
            )
            return response.xpath('//@id')[0]
        except (GvmError, IndexError) as e:
            logger.error(f"Target creation failed: {str(e)}")
            raise

    def _create_task(self, gmp: Gmp, target_id: str, config_id: str) -> str:
        """Create scan task"""
        try:
            response = gmp.create_task(
                name=f"Scan Task {datetime.now().strftime('%Y%m%d-%H%M%S')}",
                config_id=config_id,
                target_id=target_id,
                scanner_id=self.default_configs['scanner']
            )
            task_id = response.xpath('//@id')[0]
            
            # Start the task
            start_resp = gmp.start_task(task_id)
            if start_resp.xpath('//@status')[0] != '202':
                raise GvmError("Failed to start task")
                
            return task_id
            
        except (GvmError, IndexError) as e:
            logger.error(f"Task creation failed: {str(e)}")
            raise

    def get_scan_status(self, task_id: str) -> Dict:
        """Get current scan status"""
        try:
            with self._get_gmp_connection() as gmp:
                task = gmp.get_task(task_id)
                status = task.xpath('//task/status/text()')[0]
                progress = task.xpath('//task/progress/text()')[0]
                
                return {
                    'task_id': task_id,
                    'status': status,
                    'progress': progress,
                    'timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            logger.error(f"Status check failed: {str(e)}")
            return {
                'task_id': task_id,
                'status': 'error',
                'error': str(e)
            }

    def get_results(self, task_id: str, min_severity: float = 0.0) -> Dict:
        """Retrieve scan results with severity filtering"""
        try:
            with self._get_gmp_connection() as gmp:
                task = gmp.get_task(task_id)
                
                if task.xpath('//task/status/text()')[0] != 'Done':
                    return {
                        'status': 'incomplete',
                        'task_id': task_id
                    }
                
                report_id = task.xpath('//task/last_report/report/@id')[0]
                report = gmp.get_report(
                    report_id,
                    report_format_id="a994b278-1f62-11e1-96ac-406186ea4fc5",
                    filter_string=f"apply_overrides=1 levels=hmlg min_qod=70 severity>={min_severity}"
                )
                
                findings = self._parse_report(report)
                
                return {
                    'status': 'completed',
                    'task_id': task_id,
                    'report_id': report_id,
                    'summary': self._generate_summary(findings),
                    'findings': findings,
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Result retrieval failed: {str(e)}")
            return {
                'status': 'error',
                'task_id': task_id,
                'error': str(e)
            }

    def _parse_report(self, report: etree.Element) -> Dict:
        """Parse XML report into structured data"""
        findings = {
            'critical': [], 'high': [], 'medium': [], 'low': [], 'info': [],
            'total': 0, 'hosts': set(), 'ports': set()
        }
        
        for result in report.xpath('//report/results/result'):
            try:
                severity = float(result.xpath('severity/text()')[0])
                if severity < 0:  # Handle negative values (info findings)
                    severity = 0
                
                finding = {
                    'id': result.xpath('@id')[0],
                    'name': result.xpath('name/text()')[0],
                    'description': result.xpath('description/text()')[0],
                    'host': result.xpath('host/text()')[0],
                    'port': result.xpath('port/text()')[0] if result.xpath('port/text()') else 'general',
                    'severity': severity,
                    'qod': int(result.xpath('qod/value/text()')[0]),
                    'nvt': {
                        'oid': result.xpath('nvt/@oid')[0],
                        'family': result.xpath('nvt/family/text()')[0]
                    },
                    'threat': result.xpath('threat/text()')[0].lower(),
                    'timestamp': result.xpath('creation_time/text()')[0]
                }
                
                # Categorize by severity
                if severity >= 7.0:
                    findings['critical'].append(finding)
                elif severity >= 4.0:
                    findings['high'].append(finding)
                elif severity >= 2.0:
                    findings['medium'].append(finding)
                elif severity > 0:
                    findings['low'].append(finding)
                else:
                    findings['info'].append(finding)
                
                findings['total'] += 1
                findings['hosts'].add(finding['host'])
                if finding['port'] != 'general':
                    findings['ports'].add(finding['port'])
                    
            except Exception as e:
                logger.warning(f"Failed to parse result: {str(e)}")
                continue
                
        findings['hosts'] = list(findings['hosts'])
        findings['ports'] = list(findings['ports'])
        return findings

    def _generate_summary(self, findings: Dict) -> Dict:
        """Generate comprehensive scan summary"""
        return {
            'total_vulnerabilities': findings['total'],
            'affected_hosts': len(findings['hosts']),
            'affected_ports': len(findings['ports']),
            'critical': len(findings['critical']),
            'high': len(findings['high']),
            'medium': len(findings['medium']),
            'low': len(findings['low']),
            'info': len(findings['info']),
            'severity_distribution': {
                'critical': self._percentage(len(findings['critical']), findings['total']),
                'high': self._percentage(len(findings['high']), findings['total']),
                'medium': self._percentage(len(findings['medium']), findings['total']),
                'low': self._percentage(len(findings['low']), findings['total']),
                'info': self._percentage(len(findings['info']), findings['total'])
            }
        }

    def _percentage(self, part: int, whole: int) -> float:
        """Calculate percentage"""
        return round((part / whole) * 100, 2) if whole > 0 else 0.0

    def cleanup(self, task_id: str, target_id: str) -> bool:
        """Clean up scan resources"""
        try:
            with self._get_gmp_connection() as gmp:
                gmp.delete_task(task_id)
                gmp.delete_target(target_id)
                return True
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")
            return False

    def get_configurations(self) -> Dict:
        """Get available scan configurations"""
        try:
            with self._get_gmp_connection() as gmp:
                return {
                    'scan_configs': self._get_scan_configs(gmp),
                    'port_lists': self._get_port_lists(gmp),
                    'scanners': self._get_scanners(gmp)
                }
        except Exception as e:
            logger.error(f"Configuration retrieval failed: {str(e)}")
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