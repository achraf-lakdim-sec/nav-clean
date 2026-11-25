import socket
import subprocess
import ipaddress
import json
import os
import logging
from typing import Optional, Dict, List, Any

# Configure logging
logger = logging.getLogger(__name__)

try:
    import netifaces
except ImportError:
    netifaces = None
    logger.warning("netifaces not installed - using fallback network detection")

try:
    import psutil
except ImportError:
    psutil = None
    logger.warning("psutil not installed - using fallback network detection")

CONFIG_FILE = "scanner_config.json"

def find_local_ip() -> Optional[str]:
    """Find the local IP address"""
    try:
        logger.info("Attempting to find local IP using socket connection...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        logger.info(f"Found local IP via socket: {local_ip}")
        return local_ip
    except Exception as e:
        logger.warning(f"Socket method failed: {e}")
        
    try:
        logger.info("Attempting to find local IP using hostname...")
        local_ip = socket.gethostbyname(socket.gethostname())
        if local_ip.startswith("127."):
            hostname = socket.getfqdn()
            local_ip = socket.gethostbyname(hostname)
        
        if not local_ip.startswith("127."):
            logger.info(f"Found local IP via hostname: {local_ip}")
            return local_ip
        else:
            logger.warning(f"Hostname method returned localhost: {local_ip}")
            return None
    except Exception as e:
        logger.error(f"Hostname method failed: {e}")
        return None

def find_subnet_mask() -> Optional[str]:
    """Find the subnet mask for the current network interface"""
    logger.info("Attempting to find subnet mask...")
    
    if netifaces:
        try:
            logger.info("Using netifaces for subnet mask detection...")
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for addr in addrs:
                    if 'addr' in addr and not addr['addr'].startswith('127.'):
                        mask = addr.get('netmask')
                        logger.info(f"Found netmask via netifaces: {mask} for interface {iface}")
                        return mask
        except Exception as e:
            logger.warning(f"netifaces method failed: {e}")
    
    if psutil:
        try:
            logger.info("Using psutil for subnet mask detection...")
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        logger.info(f"Found netmask via psutil: {addr.netmask} for interface {iface}")
                        return addr.netmask
        except Exception as e:
            logger.warning(f"psutil method failed: {e}")
    
    logger.warning("Using default netmask 255.255.255.0 (/24)")
    return "255.255.255.0"  # Default to /24 if detection fails

def find_network_interface() -> Optional[str]:
    """Find the network interface name"""
    logger.info("Attempting to find network interface...")
    
    if netifaces:
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for addr in addrs:
                    if 'addr' in addr and not addr['addr'].startswith('127.'):
                        logger.info(f"Found interface via netifaces: {iface}")
                        return iface
        except Exception as e:
            logger.warning(f"netifaces interface detection failed: {e}")
    
    if psutil:
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        logger.info(f"Found interface via psutil: {iface}")
                        return iface
        except Exception as e:
            logger.warning(f"psutil interface detection failed: {e}")
    
    logger.warning("Could not detect network interface, returning 'Unknown'")
    return "Unknown"

def find_subnet_range(ip: str) -> Optional[ipaddress.IPv4Network]:
    """Find the subnet range for a given IP address"""
    try:
        logger.info(f"Finding subnet range for IP: {ip}")
        mask = find_subnet_mask()
        if mask:
            network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            logger.info(f"Found subnet range: {network}")
            return network
        else:
            logger.error("Could not find subnet mask")
            return None
    except Exception as e:
        logger.error(f"Failed to find subnet range: {e}")
        return None

def ip_range(network: ipaddress.IPv4Network) -> Dict[str, str]:
    """Get information about an IP network range"""
    try:
        logger.info(f"Getting IP range info for network: {network}")
        hosts = list(network.hosts())
        result = {
            "network": str(network.network_address),
            "broadcast": str(network.broadcast_address),
            "subnet_mask": str(network.netmask),
            "num_hosts": str(len(hosts)),
            "first_host": str(hosts[0]) if hosts else "None",
            "last_host": str(hosts[-1]) if hosts else "None",
            "cidr": str(network)
        }
        logger.info(f"IP range info: {result}")
        return result
    except Exception as e:
        logger.error(f"Failed to get IP range info: {e}")
        raise

# Enhanced functions to add to scanner_core.py

def run_nmap_scan(target: str, ports: str = "22,80,443", aggressive: bool = False, scripts: bool = False, timeout: int = 300) -> str:
    """Run an nmap scan with specified parameters - Enhanced version"""
    try:
        logger.info(f"Starting nmap scan - Target: {target}, Ports: {ports}, Aggressive: {aggressive}, Scripts: {scripts}")
        cmd = ["nmap"]
        
        if aggressive:
            # Aggressive scan includes OS detection, version detection, script scanning, and traceroute
            cmd.append("-A")
            if ports != "22,80,443":  # If custom ports specified with aggressive
                cmd.extend(["-p", ports])
        else:
            # Standard scan options
            cmd.extend(["-p", ports, "-sV", "--open", "-T4"])
        
        # Add script options
        if scripts and not aggressive:  # Don't add scripts if aggressive (already included)
            logger.info("Adding vulnerability scripts to scan")
            cmd.extend(["--script", "default,vuln,discovery"])
            # Increase timeout for script scans
            if timeout < 600:
                timeout = 600
                logger.info(f"Increased timeout to {timeout}s for script scan")
        
        # Add target
        cmd.append(target)
        
        logger.info(f"Running command: {' '.join(cmd)}")
        logger.info(f"Timeout set to: {timeout} seconds")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            logger.info("Nmap scan completed successfully")
            output = result.stdout
            
            # Log some statistics about the output
            lines = output.split('\n')
            logger.info(f"Scan output: {len(lines)} lines, {len(output)} characters")
            
            # Check for script output indicators
            if scripts or aggressive:
                script_indicators = ["NSE:", "| ", "vulners:", "ssl-", "http-", "CVE-", "VULNERABLE"]
                script_lines = [line for line in lines if any(indicator in line for indicator in script_indicators)]
                logger.info(f"Script output detected: {len(script_lines)} lines with script indicators")
                
                if script_lines:
                    logger.info("Sample script output:")
                    for line in script_lines[:3]:  # Log first 3 script lines
                        logger.info(f"  {line.strip()}")
            
            return output
        else:
            logger.error(f"Nmap scan failed with return code {result.returncode}")
            logger.error(f"Stderr: {result.stderr}")
            return f"[ERROR] Scan failed with return code {result.returncode}: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        logger.error(f"Nmap scan timed out after {timeout} seconds")
        return f"[ERROR] Scan timed out after {timeout} seconds. Try increasing timeout for script scans."
    except FileNotFoundError:
        logger.error("Nmap not found - please install nmap")
        return "[ERROR] Nmap not found. Please install nmap."
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        return f"[ERROR] Scan failed: {str(e)}"

def scan_subnet(subnet: str, ports: str = "22,80,443", use_scripts: bool = False, timeout: int = 300) -> Optional[str]:
    """Scan a subnet with specified parameters - Enhanced version"""
    try:
        logger.info(f"Starting subnet scan - Subnet: {subnet}, Ports: {ports}, Scripts: {use_scripts}, Timeout: {timeout}")
        cmd = ["nmap", "-p", ports, "-sV", "--open", "-T4"]
        
        if use_scripts:
            logger.info("Adding vulnerability scripts to subnet scan")
            cmd.extend(["--script", "default,vuln,discovery"])
            # Ensure adequate timeout for script scans
            if timeout < 600:
                timeout = 900
                logger.info(f"Increased timeout to {timeout}s for script scan")
        
        cmd.append(subnet)
        
        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            logger.info("Subnet scan completed successfully")
            output = result.stdout
            
            # Log scan statistics
            lines = output.split('\n')
            hosts_up = output.count('Nmap scan report for')
            open_ports = len([line for line in lines if '/tcp' in line and 'open' in line])
            
            logger.info(f"Subnet scan results: {hosts_up} hosts up, {open_ports} open ports")
            
            # Check for script output if scripts were enabled
            if use_scripts:
                script_indicators = ["NSE:", "| ", "vulners:", "ssl-", "http-", "CVE-", "VULNERABLE"]
                script_lines = [line for line in lines if any(indicator in line for indicator in script_indicators)]
                logger.info(f"Script output detected: {len(script_lines)} lines with script indicators")
                
                vulnerabilities = len([line for line in lines if 'VULNERABLE' in line or 'CVE-' in line])
                if vulnerabilities > 0:
                    logger.warning(f"Potential vulnerabilities found: {vulnerabilities}")
            
            return output
        else:
            logger.error(f"Subnet scan failed with return code {result.returncode}")
            return f"[ERROR] Subnet scan failed: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        logger.error(f"Subnet scan timed out after {timeout} seconds")
        return f"[ERROR] Subnet scan timed out after {timeout} seconds. Try increasing timeout for script scans."
    except FileNotFoundError:
        logger.error("Nmap not found - please install nmap")
        return "[ERROR] Nmap not found. Please install nmap."
    except Exception as e:
        logger.error(f"Subnet scan failed: {e}")
        return f"[ERROR] Subnet scan failed: {e}"

def scan_target(target: str, ports: str = "22,80,443", use_scripts: bool = False, timeout: int = 300) -> Optional[str]:
    """Scan a specific target with specified parameters - Enhanced version"""
    try:
        logger.info(f"Starting target scan - Target: {target}, Ports: {ports}, Scripts: {use_scripts}, Timeout: {timeout}")
        cmd = ["nmap", "-p", ports, "-sV", "--open", "-T4"]
        
        if use_scripts:
            logger.info("Adding vulnerability scripts to target scan")
            cmd.extend(["--script", "default,vuln,discovery"])
            # Ensure adequate timeout for script scans
            if timeout < 600:
                timeout = 900
                logger.info(f"Increased timeout to {timeout}s for script scan")
        
        cmd.append(target)
        
        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            logger.info("Target scan completed successfully")
            output = result.stdout
            
            # Log scan statistics
            lines = output.split('\n')
            open_ports = len([line for line in lines if '/tcp' in line and 'open' in line])
            
            logger.info(f"Target scan results: {open_ports} open ports on {target}")
            
            # Check for script output if scripts were enabled
            if use_scripts:
                script_indicators = ["NSE:", "| ", "vulners:", "ssl-", "http-", "CVE-", "VULNERABLE"]
                script_lines = [line for line in lines if any(indicator in line for indicator in script_indicators)]
                logger.info(f"Script output detected: {len(script_lines)} lines with script indicators")
                
                vulnerabilities = len([line for line in lines if 'VULNERABLE' in line or 'CVE-' in line])
                if vulnerabilities > 0:
                    logger.warning(f"Potential vulnerabilities found on {target}: {vulnerabilities}")
            
            return output
        else:
            logger.error(f"Target scan failed with return code {result.returncode}")
            return f"[ERROR] Target scan failed: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        logger.error(f"Target scan timed out after {timeout} seconds")
        return f"[ERROR] Target scan timed out after {timeout} seconds. Try increasing timeout for script scans."
    except FileNotFoundError:
        logger.error("Nmap not found - please install nmap")
        return "[ERROR] Nmap not found. Please install nmap."
    except Exception as e:
        logger.error(f"Target scan failed: {e}")
        return f"[ERROR] Target scan failed: {e}"

def run_aggressive_scan(target: str, timeout: int = 600) -> Optional[str]:
    """Run an aggressive nmap scan - Enhanced version"""
    try:
        logger.info(f"Starting aggressive scan - Target: {target}, Timeout: {timeout}")
        # Aggressive scan includes OS detection, version detection, script scanning, and traceroute
        cmd = ["nmap", "-A", "-T4", target]
        
        # Increase timeout for aggressive scans as they include scripts
        if timeout < 900:
            timeout = 900
            logger.info(f"Increased timeout to {timeout}s for aggressive scan")
        
        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            logger.info("Aggressive scan completed successfully")
            output = result.stdout
            
            # Log scan statistics
            lines = output.split('\n')
            hosts_up = output.count('Nmap scan report for')
            open_ports = len([line for line in lines if '/tcp' in line and 'open' in line])
            
            logger.info(f"Aggressive scan results: {hosts_up} hosts up, {open_ports} open ports")
            
            # Aggressive scans always include scripts
            script_indicators = ["NSE:", "| ", "vulners:", "ssl-", "http-", "CVE-", "VULNERABLE", "OS details:", "Service Info:"]
            script_lines = [line for line in lines if any(indicator in line for indicator in script_indicators)]
            logger.info(f"Aggressive scan output: {len(script_lines)} lines with detailed information")
            
            vulnerabilities = len([line for line in lines if 'VULNERABLE' in line or 'CVE-' in line])
            if vulnerabilities > 0:
                logger.warning(f"Potential vulnerabilities found: {vulnerabilities}")
            
            return output
        else:
            logger.error(f"Aggressive scan failed with return code {result.returncode}")
            return f"[ERROR] Aggressive scan failed: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        logger.error(f"Aggressive scan timed out after {timeout} seconds")
        return f"[ERROR] Aggressive scan timed out after {timeout} seconds. Consider using a longer timeout."
    except FileNotFoundError:
        logger.error("Nmap not found - please install nmap")
        return "[ERROR] Nmap not found. Please install nmap."
    except Exception as e:
        logger.error(f"Aggressive scan failed: {e}")
        return f"[ERROR] Aggressive scan failed: {e}"

def test_nmap_scripts() -> Dict[str, Any]:
    """Test if nmap scripts are working properly"""
    try:
        logger.info("Testing nmap script functionality...")
        
        # Test basic script functionality
        cmd = ["nmap", "--script", "banner", "-p", "80", "127.0.0.1"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        scripts_available = result.returncode == 0
        
        # Check if script database exists
        script_db_check = subprocess.run(["nmap", "--script-updatedb"], capture_output=True, text=True, timeout=30)
        script_db_updated = script_db_check.returncode == 0
        
        # List available script categories
        script_help = subprocess.run(["nmap", "--script-help", "vuln"], capture_output=True, text=True, timeout=30)
        vuln_scripts_available = "vuln" in script_help.stdout and script_help.returncode == 0
        
        return {
            "scripts_available": scripts_available,
            "script_db_updated": script_db_updated,
            "vuln_scripts_available": vuln_scripts_available,
            "nmap_version": get_nmap_version(),
            "test_output": result.stdout[:200] if result.stdout else "No output",
            "recommendations": get_script_recommendations(scripts_available, vuln_scripts_available)
        }
        
    except Exception as e:
        logger.error(f"Script test failed: {e}")
        return {
            "scripts_available": False,
            "error": str(e),
            "recommendations": ["Install nmap", "Update nmap to latest version", "Run 'nmap --script-updatedb'"]
        }

def get_nmap_version() -> str:
    """Get nmap version"""
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            return version_line
        return "Unknown"
    except:
        return "Not installed"

def get_script_recommendations(scripts_available: bool, vuln_scripts_available: bool) -> List[str]:
    """Get recommendations for script configuration"""
    recommendations = []
    
    if not scripts_available:
        recommendations.extend([
            "Install nmap with script support",
            "Update nmap to latest version",
            "Check nmap installation path"
        ])
    else:
        if not vuln_scripts_available:
            recommendations.extend([
                "Update nmap script database: nmap --script-updatedb",
                "Install nmap-scripts package if separate",
                "Check vulnerability script availability"
            ])
        else:
            recommendations.extend([
                "Scripts are working properly",
                "Consider running script-updatedb periodically",
                "Use longer timeouts for script scans (600+ seconds)"
            ])
    
    return recommendations
def load_config() -> Dict:
    """Load configuration from file"""
    default_config = {
        "default_ports": "22,80,443,8080,3389",
        "default_timeout": 300,
        "use_scripts": False
    }
    
    if os.path.exists(CONFIG_FILE):
        try:
            logger.info(f"Loading config from {CONFIG_FILE}")
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                default_config.update(config)
            logger.info("Config loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
    else:
        logger.info(f"Config file {CONFIG_FILE} not found, using defaults")
    
    return default_config

def save_config(config: Dict) -> None:
    """Save configuration to file"""
    try:
        logger.info(f"Saving config to {CONFIG_FILE}")
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        logger.info("Config saved successfully")
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        raise
