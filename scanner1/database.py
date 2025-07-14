import sqlite3
import logging
from typing import List, Dict, Optional, Union
from datetime import datetime
from pathlib import Path

# Initialize logging
logger = logging.getLogger(__name__)

class ScanDatabase:
    """Enhanced SQLite database for vulnerability scan results with:
    - Robust error handling
    - Data validation
    - Schema versioning
    - Bulk operations
    - Backup/restore
    """
    
    SCHEMA_VERSION = 3  # Incremented version
    
    def __init__(self, db_path: str = "scanner.db"):
        self.db_path = Path(db_path)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database with proper schema"""
        try:
            with self._get_connection() as conn:
                # Enable foreign keys and performance optimizations
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
                
                # Check if we need to create/update tables
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                if version < self.SCHEMA_VERSION:
                    self._create_tables(conn)
                    conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
                    
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {str(e)}")
            raise RuntimeError(f"Could not initialize database: {str(e)}")
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with proper settings"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    def _create_tables(self, conn: sqlite3.Connection) -> None:
        """Create or update database tables with proper schema"""
        try:
            cursor = conn.cursor()
            
            # Create tables with proper schema
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT CHECK(status IN ('completed', 'failed', 'running')),
                    num_hosts INTEGER,
                    num_vulnerabilities INTEGER
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    host_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER REFERENCES scans(scan_id) ON DELETE CASCADE,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    os_name TEXT,
                    os_accuracy INTEGER,
                    os_vendor TEXT,
                    os_family TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(ip, scan_id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ports (
                    port_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER REFERENCES hosts(host_id) ON DELETE CASCADE,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service TEXT,
                    version TEXT,
                    state TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(host_id, port, protocol)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    port_id INTEGER REFERENCES ports(port_id) ON DELETE CASCADE,
                    cve_id TEXT NOT NULL,
                    cvss_score REAL,
                    severity TEXT,
                    description TEXT,
                    exploit_available BOOLEAN DEFAULT 0,
                    recommendation TEXT,
                    first_detected TEXT NOT NULL,
                    last_detected TEXT NOT NULL,
                    UNIQUE(port_id, cve_id)
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ports_service ON ports(service)")
            
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            raise RuntimeError(f"Table creation failed: {str(e)}")

    def save_scan(self, target: str) -> Optional[int]:
        """Create a new scan record"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scans (target, start_time, status)
                    VALUES (?, ?, ?)
                """, (
                    str(target),
                    datetime.now().isoformat(),
                    'running'
                ))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Failed to save scan: {str(e)}")
            return None
    
    def save_host(self, scan_id: int, host_data: Dict) -> Optional[int]:
        """Save host information to database"""
        try:
            ports = host_data.get('ports', [])
            host_data_clean = self._validate_host_data(host_data)
            os_info = host_data_clean.get('os', {})
            now = datetime.now().isoformat()
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO hosts (
                    scan_id, ip, hostname, os_name, os_accuracy, os_vendor, os_family, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    host_data_clean['ip'],
                    host_data_clean.get('hostname'),
                    os_info.get('name', 'unknown'),
                    os_info.get('accuracy', 0),
                    os_info.get('vendor', 'unknown'),
                    os_info.get('family', 'unknown'),
                    now,
                    now
                )
            )
            host_id = cursor.lastrowid
            for port in ports:
                port_id = self._save_port(conn, host_id, port)
                for vuln in port.get('cves', []):
                    self._save_vulnerability(conn, port_id, vuln)
            conn.commit()
            return host_id
        except sqlite3.Error as e:
            logger.error(f"DB error: {e}")
            return None
    
    def _save_port(self, conn: sqlite3.Connection, host_id: int, port_data: Dict) -> int:
        """Save port information"""
        validated = self._validate_port_data(port_data)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO ports (
                host_id, port, protocol, service, version, state, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                service = excluded.service,
                version = excluded.version,
                state = excluded.state,
                last_seen = excluded.last_seen
            RETURNING port_id
        """, (
            host_id,
            validated['port'],
            validated['protocol'],
            validated['service'],
            validated['version'],
            validated['state'],
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        port_id = cursor.fetchone()[0]
        
        # Save vulnerabilities
        for vuln in validated['cves']:
            self._save_vulnerability(conn, port_id, vuln)
            
        return port_id
    
    def _save_vulnerability(self, conn: sqlite3.Connection, port_id: int, vuln_data: Dict) -> int:
        """Save vulnerability information"""
        validated = self._validate_vuln_data(vuln_data)
        severity = self._get_severity(validated['score'])
        
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO vulnerabilities (
                port_id, cve_id, cvss_score, severity, description,
                exploit_available, recommendation, first_detected, last_detected
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(port_id, cve_id) DO UPDATE SET
                cvss_score = excluded.cvss_score,
                severity = excluded.severity,
                description = excluded.description,
                exploit_available = excluded.exploit_available,
                last_detected = excluded.last_detected
            RETURNING vuln_id
        """, (
            port_id,
            validated['id'],
            validated['score'],
            severity,
            validated['description'],
            False,  # Would check exploit DB in real implementation
            f"Update {validated.get('service', 'affected software')}",
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        return cursor.fetchone()[0]
    
    def complete_scan(self, scan_id: int, num_hosts: int, num_vulnerabilities: int) -> bool:
        """Mark a scan as completed with statistics"""
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE scans 
                    SET end_time = ?, status = 'completed',
                        num_hosts = ?, num_vulnerabilities = ?
                    WHERE scan_id = ?
                """, (
                    datetime.now().isoformat(),
                    num_hosts,
                    num_vulnerabilities,
                    scan_id
                ))
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error(f"Failed to complete scan {scan_id}: {str(e)}")
            return False
    
    # Data validation methods
    def _validate_host_data(self, data: Dict) -> Dict:
        """Validate and normalize host data"""
        return {
            'ip': str(data.get('ip', '')).strip(),
            'hostname': str(data.get('hostname', '')).strip() or None,
            'os': self._validate_os_data(data.get('os')),
            'ports': [self._validate_port_data(p) for p in data.get('ports', [])]
        }
    
    def _validate_os_data(self, os_data: Union[Dict, str, None]) -> Dict:
        """Standardize OS information structure"""
        if isinstance(os_data, str):
            return {
                'name': os_data,
                'accuracy': 0,
                'vendor': 'unknown',
                'family': 'unknown'
            }
        elif not isinstance(os_data, dict):
            return {
                'name': 'unknown',
                'accuracy': 0,
                'vendor': 'unknown',
                'family': 'unknown'
            }
        return {
            'name': str(os_data.get('name', 'unknown')),
            'accuracy': int(os_data.get('accuracy', 0)),
            'vendor': str(os_data.get('vendor', 'unknown')),
            'family': str(os_data.get('family', 'unknown'))
        }
    
    def _validate_port_data(self, data: Dict) -> Dict:
        """Validate and normalize port data"""
        return {
            'port': int(data['port']),
            'protocol': str(data.get('protocol', 'tcp')).lower(),
            'service': str(data.get('service', 'unknown')),
            'version': str(data.get('version', 'unknown')),
            'state': str(data.get('state', 'open')).lower(),
            'cves': [self._validate_vuln_data(v) for v in data.get('cves', [])]
        }
    
    def _validate_vuln_data(self, data: Dict) -> Dict:
        """Validate vulnerability data"""
        return {
            'id': str(data['id']).upper(),
            'score': float(data.get('score', 0.0)),
            'description': str(data.get('description', ''))
        }
    
    def _get_severity(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0: return 'critical'
        if score >= 7.0: return 'high'
        if score >= 4.0: return 'medium'
        return 'low'
    
    # Query methods
    def get_historical_vulnerabilities(self, ip: str) -> List[Dict]:
        """Get all vulnerabilities for a host"""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("""
                SELECT v.*, p.port, p.protocol, p.service, p.version
                FROM vulnerabilities v
                JOIN ports p ON v.port_id = p.port_id
                JOIN hosts h ON p.host_id = h.host_id
                WHERE h.ip = ?
                ORDER BY v.severity DESC, v.cvss_score DESC
            """, (ip,))]
    
    def get_host_history(self, ip: str) -> List[Dict]:
        """Get scan history for a host"""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("""
                SELECT s.scan_id, s.start_time, s.end_time,
                       COUNT(DISTINCT p.port_id) as ports_found,
                       COUNT(DISTINCT v.vuln_id) as vulns_found
                FROM hosts h
                JOIN scans s ON h.scan_id = s.scan_id
                LEFT JOIN ports p ON h.host_id = p.host_id
                LEFT JOIN vulnerabilities v ON p.port_id = v.port_id
                WHERE h.ip = ?
                GROUP BY s.scan_id
                ORDER BY s.start_time DESC
            """, (ip,))]
    
    def backup_database(self, backup_path: str) -> bool:
        """Create a backup of the database"""
        try:
            conn = self._get_connection()
            with sqlite3.connect(backup_path) as backup:
                conn.backup(backup)
            return True
        except sqlite3.Error as e:
            logger.error(f"Backup failed: {str(e)}")
            return False