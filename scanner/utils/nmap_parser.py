import logging
from typing import Dict, List, Optional
from datetime import datetime
from .models import Host, Port, Vulnerability  # Assuming you have these models

logger = logging.getLogger(__name__)

def parse_nmap_results(nmap_scan_data: Dict) -> List[Host]:
    """
    Parse raw Nmap scan results into structured Host objects
    
    Args:
        nmap_scan_data: Raw data from python-nmap PortScanner
    
    Returns:
        List of Host objects with parsed scan data
    """
    hosts = []
    
    for host in nmap_scan_data.all_hosts():
        try:
            # Parse OS information
            os_info = parse_os_info(nmap_scan_data[host])
            
            # Parse ports and services
            ports = []
            for proto in nmap_scan_data[host].all_protocols():
                for port, port_data in nmap_scan_data[host][proto].items():
                    port_obj = parse_port_info(port, proto, port_data)
                    if port_obj:
                        ports.append(port_obj)
            
            hosts.append(Host(
                ip=host,
                hostname=nmap_scan_data[host].hostname() or "",
                os=os_info,
                ports=ports
            ))
            
        except Exception as e:
            logger.error(f"Error parsing host {host}: {str(e)}")
            continue
    
    return hosts

def parse_os_info(host_data: Dict) -> Dict:
    """Parse OS detection results from Nmap scan"""
    os_matches = host_data.get('osmatch', [])
    best_os = {
        'name': 'unknown',
        'accuracy': 0,
        'type': 'unknown',
        'vendor': 'unknown',
        'family': 'unknown',
        'cpe': []
    }
    
    if os_matches:
        # Get the best match (highest accuracy)
        best_match = max(os_matches, key=lambda x: int(x.get('accuracy', 0)))
        best_os.update({
            'name': best_match.get('name', 'unknown'),
            'accuracy': best_match.get('accuracy', 0),
            'type': best_match.get('type', 'unknown'),
            'vendor': best_match.get('vendor', 'unknown'),
            'family': best_match.get('osfamily', 'unknown'),
            'cpe': best_match.get('osclass', {}).get('cpe', [])
        })
    
    return best_os

def parse_port_info(port: int, protocol: str, port_data: Dict) -> Optional[Port]:
    """Parse individual port information from Nmap results"""
    try:
        service = port_data['name']
        version = port_data.get('version', 'unknown')
        product = port_data.get('product', '')
        
        # Combine product and service if available
        if product and product != service:
            service = f"{product} {service}"
        
        # Parse any script output
        scripts = parse_nmap_scripts(port_data.get('script', {}))
        
        return Port(
            number=port,
            protocol=protocol,
            service=service,
            version=version,
            state=port_data.get('state', 'open'),
            cves=[],  # Will be populated by CVE lookup later
            scripts=scripts
        )
    except KeyError as e:
        logger.warning(f"Missing expected port data for {port}/{protocol}: {str(e)}")
        return None

def parse_nmap_scripts(script_data: Dict) -> Dict:
    """Parse Nmap script output into structured data"""
    scripts = {}
    
    for script_name, script_output in script_data.items():
        # Handle different script output formats
        if isinstance(script_output, str):
            scripts[script_name] = {'output': script_output}
        elif isinstance(script_output, dict):
            scripts[script_name] = script_output
        elif isinstance(script_output, list):
            scripts[script_name] = {'items': script_output}
    
    return scripts

def filter_interesting_ports(ports: List[Port]) -> List[Port]:
    """Filter out uninteresting ports (like closed/filtered)"""
    return [
        port for port in ports 
        if port.state.lower() == 'open' 
        and port.service.lower() not in ['tcpwrapped', 'unknown']
    ]