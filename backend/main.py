from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from typing import Optional, Dict, Any, List
from scanner_core import (
    run_nmap_scan, find_local_ip, find_subnet_range, scan_subnet, 
    ip_range, run_aggressive_scan, scan_target
)
from validation import validate_target, validate_ports
import json
import traceback
import logging
import os
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="NAV-Scanner API", version="2.0.0")

# Only the NAV front end may call the API from a browser. Override with a
# comma-separated list in NAV_ALLOWED_ORIGINS if you serve it elsewhere.
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "NAV_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def block_cross_site_requests(request: Request, call_next):
    """Refuse requests that another website makes through the user's browser.

    CORS only stops a foreign page from reading responses. Since scans are
    triggered by GET requests, a malicious page could still fire them, so
    requests from unknown origins are rejected before reaching any endpoint.
    """
    origin = request.headers.get("origin")
    fetch_site = request.headers.get("sec-fetch-site")
    if origin and origin not in ALLOWED_ORIGINS:
        return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})
    if not origin and fetch_site == "cross-site":
        return JSONResponse(status_code=403, content={"detail": "Cross-site request blocked"})
    return await call_next(request)

# Pydantic models for request/response
class ScanHistoryItem(BaseModel):
    id: int
    type: str
    target: str
    status: str
    startTime: str
    endTime: str
    ports: Optional[str] = "22,80,443"
    useScripts: bool = False
    result: Optional[str] = ""
    devicesFound: int = 0
    hostsUp: int = 0
    hostsDown: int = 0
    openPorts: int = 0
    closedPorts: int = 0
    totalPorts: int = 0
    services: List[Dict[str, Any]] = []
    vulnerabilities: int = 0
    vulnerabilityDetails: List[Dict[str, Any]] = []
    duration: str = "Unknown"
    error: Optional[str] = None
    timestamp: str

class NetworkDetectionResponse(BaseModel):
    local_ip: str
    subnet_info: Dict[str, str]
    interface: str

class ScanResponse(BaseModel):
    type: str
    target: Optional[str] = None
    subnet: Optional[str] = None
    ports: Optional[str] = None
    result: str

# File paths
SCAN_HISTORY_FILE = "scan_history.json"
CONFIG_FILE = "scanner_config.json"

def load_scan_history() -> List[Dict]:
    """Load scan history from file"""
    try:
        if os.path.exists(SCAN_HISTORY_FILE):
            with open(SCAN_HISTORY_FILE, "r") as f:
                history = json.load(f)
                return history if isinstance(history, list) else []
        return []
    except Exception as e:
        logger.error(f"Error loading scan history: {e}")
        return []

def save_scan_history(history: List[Dict]) -> bool:
    """Save scan history to file"""
    try:
        # Keep only the last 100 scans
        history = history[:100]
        with open(SCAN_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2, default=str)
        return True
    except Exception as e:
        logger.error(f"Error saving scan history: {e}")
        return False

def parse_nmap_output(output: str) -> Dict[str, Any]:
    """Parse nmap output to extract structured information"""
    try:
        lines = output.split('\n')
        hosts_up = 0
        hosts_down = 0
        open_ports = 0
        closed_ports = 0
        services = []
        vulnerabilities = []
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Extract current host
            if 'Nmap scan report for' in line:
                host_match = line.split('Nmap scan report for ')
                if len(host_match) > 1:
                    current_host = host_match[1].strip()
            
            # Count open ports and extract services
            if line and line[0].isdigit() and '/tcp' in line and 'open' in line:
                open_ports += 1
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0]
                    service = ' '.join(parts[2:]) if len(parts) > 2 else 'unknown'
                    services.append({
                        'host': current_host or 'Unknown',
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
            
            # Count closed ports
            if line and line[0].isdigit() and '/tcp' in line and 'closed' in line:
                closed_ports += 1
            
            # Look for vulnerabilities
            if 'VULNERABLE' in line or 'CVE-' in line:
                vulnerabilities.append({
                    'host': current_host or 'Unknown',
                    'description': line,
                    'severity': 'unknown'
                })
            
            # Parse summary line
            if 'Nmap done:' in line and 'hosts up' in line:
                try:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'addresses' and i > 0:
                            total_scanned = int(parts[i-1])
                        if part == 'hosts' and i > 0 and parts[i+1] == 'up)':
                            hosts_up = int(parts[i-1].replace('(', ''))
                            hosts_down = total_scanned - hosts_up if 'total_scanned' in locals() else 0
                except (ValueError, IndexError):
                    pass
        
        # If no summary found, count scan reports
        if hosts_up == 0:
            hosts_up = output.count('Nmap scan report for')
        
        return {
            'hostsUp': hosts_up,
            'hostsDown': hosts_down,
            'openPorts': open_ports,
            'closedPorts': closed_ports,
            'totalPorts': open_ports + closed_ports,
            'services': services,
            'vulnerabilities': vulnerabilities
        }
    except Exception as e:
        logger.error(f"Error parsing nmap output: {e}")
        return {
            'hostsUp': 0,
            'hostsDown': 0,
            'openPorts': 0,
            'closedPorts': 0,
            'totalPorts': 0,
            'services': [],
            'vulnerabilities': []
        }

@app.get("/")
def root():
    """API root endpoint"""
    return {
        "message": "NAV-Scanner API is running",
        "version": "2.0.0",
        "endpoints": [
            "/detect", "/scan", "/quick-scan", "/full-scan", 
            "/custom-scan", "/aggressive-scan", "/script-scan",
            "/scan-history", "/save-scan-history", "/config"
        ]
    }

@app.get("/detect")
def detect_local_info() -> NetworkDetectionResponse:
    """Detect local network information"""
    try:
        logger.info("Starting network detection...")
        
        # Find local IP
        ip = find_local_ip()
        logger.info(f"Found local IP: {ip}")
        
        if not ip:
            logger.error("Could not detect local IP")
            raise HTTPException(status_code=500, detail="Could not detect local IP")
        
        # Find subnet range
        subnet = find_subnet_range(ip)
        logger.info(f"Found subnet: {subnet}")
        
        if not subnet:
            logger.error("Could not calculate subnet")
            raise HTTPException(status_code=500, detail="Could not calculate subnet")
        
        # Get IP range info
        subnet_info = ip_range(subnet)
        logger.info(f"Subnet info: {subnet_info}")
        
        # Try to get interface info
        try:
            from scanner_core import find_network_interface
            interface = find_network_interface()
        except Exception as e:
            logger.warning(f"Could not detect interface: {e}")
            interface = "Unknown"
        
        result = NetworkDetectionResponse(
            local_ip=ip,
            subnet_info=subnet_info,
            interface=interface
        )
        
        logger.info(f"Detection successful: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Detection failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Network detection failed: {str(e)}")

# Enhanced scan endpoint with better script handling
@app.get("/scan")
def scan(
    target: str = Query(..., description="IP or subnet to scan"),
    ports: str = Query("22,80,443", description="Ports to scan"),
    aggressive: bool = Query(False, description="Use aggressive scanning"),
    scripts: bool = Query(False, description="Enable vulnerability scripts")
) -> ScanResponse:
    """Generic scan endpoint with enhanced script support"""
    target = validate_target(target)
    ports = validate_ports(ports)
    try:
        logger.info(f"Starting scan - Target: {target}, Ports: {ports}, Aggressive: {aggressive}, Scripts: {scripts}")
        
        # Use longer timeout if scripts are enabled
        timeout = 1200 if scripts else 600 if aggressive else 300
        
        output = run_nmap_scan(target, ports, aggressive, scripts, timeout)
        
        scan_type = "Generic Scan"
        if aggressive:
            scan_type = "Aggressive Scan"
        elif scripts:
            scan_type = "Script Scan"
        
        return ScanResponse(
            type=scan_type,
            target=target,
            ports=ports,
            result=output
        )
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

# Add these enhanced endpoints to main.py (replace the existing ones)

@app.get("/quick-scan")
def quick_scan(scripts: bool = Query(False, description="Enable vulnerability scripts")) -> ScanResponse:
    """Quick network scan of common ports with optional script support"""
    try:
        logger.info(f"Starting quick scan - Scripts: {scripts}")
        ip = find_local_ip()
        if not ip:
            raise HTTPException(status_code=500, detail="Could not determine local IP")
        
        subnet = find_subnet_range(ip)
        if not subnet:
            raise HTTPException(status_code=500, detail="Could not determine subnet")
        
        # Use longer timeout if scripts are enabled
        timeout = 600 if scripts else 300
        result = scan_subnet(str(subnet), "22,80,443", use_scripts=scripts, timeout=timeout)
        
        return ScanResponse(
            type="Quick Scan" + (" + Scripts" if scripts else ""),
            subnet=str(subnet),
            ports="22,80,443",
            result=result or "Scan completed with no output"
        )
    except Exception as e:
        logger.error(f"Quick scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Quick scan failed: {str(e)}")

@app.get("/full-scan")
def full_scan(scripts: bool = Query(False, description="Enable vulnerability scripts")) -> ScanResponse:
    """Full network scan of top 1000 ports with optional script support"""
    try:
        logger.info(f"Starting full scan - Scripts: {scripts}")
        ip = find_local_ip()
        if not ip:
            raise HTTPException(status_code=500, detail="Could not determine local IP")
        
        subnet = find_subnet_range(ip)
        if not subnet:
            raise HTTPException(status_code=500, detail="Could not determine subnet")
        
        # Use longer timeout if scripts are enabled
        timeout = 1200 if scripts else 900
        result = scan_subnet(str(subnet), "1-1000", use_scripts=scripts, timeout=timeout)
        
        return ScanResponse(
            type="Full Scan" + (" + Scripts" if scripts else ""),
            subnet=str(subnet),
            ports="1-1000",
            result=result or "Scan completed with no output"
        )
    except Exception as e:
        logger.error(f"Full scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Full scan failed: {str(e)}")

@app.get("/custom-scan")
def custom_scan(
    ports: str = Query(..., description="Ports to scan"),
    scripts: bool = Query(False, description="Enable vulnerability scripts")
) -> ScanResponse:
    """Custom port scan with optional script support"""
    ports = validate_ports(ports)
    try:
        logger.info(f"Starting custom scan - Ports: {ports}, Scripts: {scripts}")
        ip = find_local_ip()
        if not ip:
            raise HTTPException(status_code=500, detail="Could not determine local IP")
        
        subnet = find_subnet_range(ip)
        if not subnet:
            raise HTTPException(status_code=500, detail="Could not determine subnet")
        
        # Use longer timeout if scripts are enabled
        timeout = 900 if scripts else 600
        result = scan_subnet(str(subnet), ports, use_scripts=scripts, timeout=timeout)
        
        return ScanResponse(
            type="Custom Scan" + (" + Scripts" if scripts else ""),
            subnet=str(subnet),
            ports=ports,
            result=result or "Scan completed with no output"
        )
    except Exception as e:
        logger.error(f"Custom scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Custom scan failed: {str(e)}")

@app.get("/script-scan")
def script_scan() -> ScanResponse:
    """Dedicated vulnerability script scan"""
    try:
        logger.info("Starting dedicated vulnerability script scan")
        ip = find_local_ip()
        if not ip:
            raise HTTPException(status_code=500, detail="Could not determine local IP")
        
        subnet = find_subnet_range(ip)
        if not subnet:
            raise HTTPException(status_code=500, detail="Could not determine subnet")
        
        # Always use scripts and longer timeout for this scan type
        result = scan_subnet(str(subnet), "22,80,443,8080,3389,21,23,25,53,110,143,993,995", use_scripts=True, timeout=1200)
        
        return ScanResponse(
            type="Vulnerability Scan",
            subnet=str(subnet),
            ports="22,80,443,8080,3389,21,23,25,53,110,143,993,995",
            result=result or "Scan completed with no output"
        )
    except Exception as e:
        logger.error(f"Script scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Script scan failed: {str(e)}")

@app.get("/targeted-scan")
def targeted_scan(
    target: str = Query(..., description="Specific target to scan"),
    ports: str = Query("22,80,443", description="Ports to scan"),
    scripts: bool = Query(False, description="Enable vulnerability scripts")
) -> ScanResponse:
    """Targeted scan of specific host with optional script support"""
    target = validate_target(target)
    ports = validate_ports(ports)
    try:
        logger.info(f"Starting targeted scan - Target: {target}, Ports: {ports}, Scripts: {scripts}")
        
        # Use longer timeout if scripts are enabled
        timeout = 900 if scripts else 600
        result = scan_target(target, ports, use_scripts=scripts, timeout=timeout)
        
        return ScanResponse(
            type="Targeted Scan" + (" + Scripts" if scripts else ""),
            target=target,
            ports=ports,
            result=result or "Scan completed with no output"
        )
    except Exception as e:
        logger.error(f"Targeted scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Targeted scan failed: {str(e)}")

@app.get("/aggressive-scan")
def aggressive_scan(target: str = Query("", description="Target to scan (optional)")) -> ScanResponse:
    """Aggressive scan with OS detection and service enumeration"""
    if target:
        target = validate_target(target)
    try:
        logger.info(f"Starting aggressive scan - Target: {target}")
        
        if not target:
            ip = find_local_ip()
            if not ip:
                raise HTTPException(status_code=500, detail="Could not determine local IP")
            
            subnet = find_subnet_range(ip)
            if not subnet:
                raise HTTPException(status_code=500, detail="Could not determine subnet")
            target = str(subnet)
        
        result = run_aggressive_scan(target, timeout=900)
        
        return ScanResponse(
            type="Aggressive Scan",
            target=target,
            result=result or "Scan completed with no output"
        )
    except Exception as e:
        logger.error(f"Aggressive scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Aggressive scan failed: {str(e)}")

@app.get("/scan-history")
def get_scan_history() -> List[Dict]:
    """Get scan history"""
    try:
        logger.info("Fetching scan history")
        history = load_scan_history()
        logger.info(f"Loaded {len(history)} scans from history")
        return history
    except Exception as e:
        logger.error(f"Failed to load scan history: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to load scan history: {str(e)}")

@app.post("/save-scan-history")
def save_scan_history_endpoint(scan_data: Dict[str, Any]) -> Dict[str, str]:
    """Save scan to history"""
    try:
        logger.info(f"Saving scan to history: {scan_data.get('type', 'unknown')} scan")
        
        # Load existing history
        history = load_scan_history()
        
        # Ensure scan_data has required fields
        if 'timestamp' not in scan_data:
            scan_data['timestamp'] = datetime.now().isoformat()
        
        if 'id' not in scan_data:
            scan_data['id'] = int(datetime.now().timestamp() * 1000)
        
        # Add new scan to beginning of history
        history.insert(0, scan_data)
        
        # Save updated history
        if save_scan_history(history):
            logger.info("Scan saved successfully")
            return {"message": "Scan saved successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to save scan to file")
            
    except Exception as e:
        logger.error(f"Failed to save scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to save scan: {str(e)}")

@app.delete("/scan-history/{scan_id}")
def delete_scan_from_history(scan_id: int) -> Dict[str, str]:
    """Delete specific scan from history"""
    try:
        logger.info(f"Deleting scan {scan_id} from history")
        
        history = load_scan_history()
        original_count = len(history)
        
        # Filter out the scan with matching ID
        history = [scan for scan in history if scan.get('id') != scan_id]
        
        if len(history) == original_count:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if save_scan_history(history):
            logger.info(f"Scan {scan_id} deleted successfully")
            return {"message": "Scan deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to save updated history")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete scan: {str(e)}")

@app.delete("/scan-history")
def clear_scan_history() -> Dict[str, str]:
    """Clear all scan history"""
    try:
        logger.info("Clearing all scan history")
        
        if save_scan_history([]):
            logger.info("Scan history cleared successfully")
            return {"message": "Scan history cleared successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to clear scan history")
            
    except Exception as e:
        logger.error(f"Failed to clear scan history: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to clear scan history: {str(e)}")

@app.get("/config")
def get_config() -> Dict[str, Any]:
    """Get scanner configuration"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                return config
        else:
            # Return default configuration
            default_config = {
                "default_ports": "22,80,443,8080,3389",
                "default_timeout": 300,
                "use_scripts": False,
                "max_history_items": 100,
                "scan_types": [
                    {"name": "quick", "ports": "22,80,443", "timeout": 300},
                    {"name": "full", "ports": "1-1000", "timeout": 900},
                    {"name": "custom", "ports": "22,80,443", "timeout": 600}
                ]
            }
            return default_config
    except Exception as e:
        logger.error(f"Config read failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to read configuration")

@app.post("/config")
def update_config(config: Dict[str, Any]) -> Dict[str, str]:
    """Update scanner configuration"""
    try:
        logger.info("Updating scanner configuration")
        
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        
        logger.info("Configuration updated successfully")
        return {"message": "Configuration updated successfully"}
        
    except Exception as e:
        logger.error(f"Config update failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update configuration")

@app.get("/health")
def health_check() -> Dict[str, str]:
    """Health check endpoint"""
    try:
        # Test basic functionality
        ip = find_local_ip()
        if not ip:
            return {"status": "unhealthy", "message": "Cannot detect local IP"}
        
        return {
            "status": "healthy", 
            "message": "NAV-Scanner API is running normally",
            "local_ip": ip,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {"status": "unhealthy", "message": str(e)}

@app.get("/stats")
def get_stats() -> Dict[str, Any]:
    """Get scanning statistics"""
    try:
        history = load_scan_history()
        
        total_scans = len(history)
        completed_scans = len([s for s in history if s.get('status') == 'completed'])
        failed_scans = len([s for s in history if s.get('status') == 'failed'])
        total_devices = sum(s.get('hostsUp', s.get('devicesFound', 0)) for s in history)
        total_vulnerabilities = sum(s.get('vulnerabilities', 0) for s in history)
        
        # Calculate scan type distribution
        scan_types = {}
        for scan in history:
            scan_type = scan.get('type', 'unknown')
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        
        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "success_rate": (completed_scans / total_scans * 100) if total_scans > 0 else 0,
            "total_devices_found": total_devices,
            "total_vulnerabilities": total_vulnerabilities,
            "scan_type_distribution": scan_types,
            "last_scan": history[0].get('timestamp') if history else None
        }
    except Exception as e:
        logger.error(f"Stats calculation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to calculate statistics")

# Error handlers
@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {str(exc)}")
    logger.error(traceback.format_exc())
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
