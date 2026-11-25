import { useState, useEffect } from 'react'
import axios from 'axios'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { 
  Play, 
  Square, 
  Network, 
  Settings, 
  Clock,
  AlertCircle,
  CheckCircle,
  Activity,
  Zap,
  Shield,
  Eye,
  Target,
  Loader2,
  Info
} from 'lucide-react'

const ScanConfiguration = () => {
  const [scanConfig, setScanConfig] = useState({
    target: '192.168.1.0/24',
    scanType: 'quick',
    ports: '22,80,443',
    useScripts: false,
    timeout: 300
  })

  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanStatus, setScanStatus] = useState(null)
  const [scanResults, setScanResults] = useState(null)
  const [isDetecting, setIsDetecting] = useState(false)

  const [networkInfo, setNetworkInfo] = useState({
    ip: 'Error detecting IP',
    subnet: 'N/A',
    netmask: 'N/A',
    interface: 'N/A'
  })

  const API_BASE = 'http://127.0.0.1:8000'

  const fetchNetworkInfo = async () => {
    setIsDetecting(true)
    try {
      const response = await axios.get(`${API_BASE}/detect`)
      const data = response.data
      
      if (data.error) {
        setNetworkInfo({
          ip: 'Error detecting IP',
          subnet: 'N/A',
          netmask: 'N/A',
          interface: 'N/A'
        })
      } else {
        setNetworkInfo({
          ip: data.local_ip || 'Error detecting IP',
          subnet: data.subnet_info?.cidr || 'N/A',
          netmask: data.subnet_info?.subnet_mask || 'N/A',
          interface: data.interface || 'N/A'
        })
        
        // Update target with detected subnet
        if (data.subnet_info?.cidr) {
          setScanConfig(prev => ({ ...prev, target: data.subnet_info.cidr }))
        }
      }
    } catch (error) {
      console.error('Error fetching network info:', error)
      setNetworkInfo({
        ip: 'Error detecting IP',
        subnet: 'N/A',
        netmask: 'N/A',
        interface: 'N/A'
      })
    } finally {
      setIsDetecting(false)
    }
  }

  useEffect(() => {
    fetchNetworkInfo()
  }, [])

  const scanTypes = [
    { 
      value: 'quick', 
      label: 'Quick Scan', 
      description: 'Fast scan of common ports', 
      icon: Zap, 
      color: 'text-blue-500', 
      endpoint: '/quick-scan',
      supportsScripts: true,
      supportsPorts: false,
      defaultPorts: '22,80,443'
    },
    { 
      value: 'full', 
      label: 'Full Scan', 
      description: 'Comprehensive scan of top 1000 ports', 
      icon: Target, 
      color: 'text-green-500', 
      endpoint: '/full-scan',
      supportsScripts: true, 
      supportsPorts: false,
      defaultPorts: '1-1000'
    },
    { 
      value: 'stealth', 
      label: 'Stealth Scan', 
      description: 'Slow, low-profile scan', 
      icon: Eye, 
      color: 'text-purple-500', 
      endpoint: '/scan',
      supportsScripts: true,
      supportsPorts: true,
      defaultPorts: '22,80,443'
    },
    { 
      value: 'aggressive', 
      label: 'Aggressive Scan', 
      description: 'Fast scan with OS detection', 
      icon: Activity, 
      color: 'text-red-500', 
      endpoint: '/aggressive-scan',
      supportsScripts: false, // Aggressive scan has built-in scripts
      supportsPorts: false,
      defaultPorts: 'all'
    },
    { 
      value: 'custom', 
      label: 'Custom Scan', 
      description: 'User-defined scan parameters', 
      icon: Settings, 
      color: 'text-orange-500', 
      endpoint: '/custom-scan',
      supportsScripts: true,
      supportsPorts: true,
      defaultPorts: '22,80,443'
    },
    {
      value: 'script',
      label: 'Vulnerability Scan',
      description: 'Script-based vulnerability detection',
      icon: Shield,
      color: 'text-yellow-500',
      endpoint: '/script-scan',
      supportsScripts: true, // Always enabled for this type
      supportsPorts: false,
      defaultPorts: '22,80,443'
    }
  ]

  const commonPorts = [
    { value: '22,80,443', label: 'Web Services (22,80,443)' },
    { value: '21,22,23,25,53,80,110,143,443,993,995', label: 'Common Services' },
    { value: '1-1000', label: 'Top 1000 Ports' },
    { value: '1-65535', label: 'All Ports (Slow)' }
  ]

  // Enhanced scan result parser
// Replace the parseScanResults function in ScanConfiguration.jsx with this enhanced version:

const parseScanResults = (result) => {
  console.log('Parsing scan result:', result);
  
  if (!result) return { 
    hostsUp: 0, hostsDown: 0, openPorts: 0, closedPorts: 0, 
    totalPorts: 0, services: [], vulnerabilities: [] 
  };

  if (typeof result === 'string') {
    const lines = result.split('\n');
    let hostsUp = 0;
    let hostsDown = 0;
    let openPorts = 0;
    let closedPorts = 0;
    let services = [];
    let vulnerabilities = [];
    let currentHost = null;
    let currentService = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmedLine = line.trim();
      
      // Extract current host being scanned
      if (trimmedLine.includes('Nmap scan report for')) {
        const hostMatch = trimmedLine.match(/Nmap scan report for (.+?)(\s|$)/);
        if (hostMatch) {
          currentHost = hostMatch[1].replace(/[()]/g, '').trim();
        }
      }
      
      // Count open ports and extract services
      if (trimmedLine.match(/^\d+\/\w+\s+open/)) {
        openPorts++;
        const portMatch = trimmedLine.match(/^(\d+)\/(\w+)\s+open\s+(.+)/);
        if (portMatch) {
          currentService = {
            port: portMatch[1],
            protocol: portMatch[2],
            service: portMatch[3].trim()
          };
          services.push({
            host: currentHost || 'Unknown',
            port: portMatch[1],
            service: portMatch[3].trim(),
            state: 'open'
          });
        }
      }
      
      // Count closed ports
      if (trimmedLine.match(/^\d+\/\w+\s+closed/)) {
        closedPorts++;
      }
      
      // Enhanced vulnerability detection
      const vulnPatterns = [
        /CVE-\d{4}-\d{4,}/,                    // Direct CVE mentions
        /\|\s+.*(?:VULNERABLE|vulnerable)/i,   // Nmap script output
        /\|\s+vulners:/i,                      // Vulners script output
        /\|\s+ssl-.*(?:VULNERABLE|vulnerable)/i, // SSL vulnerabilities
        /\|\s+http-.*(?:VULNERABLE|vulnerable)/i, // HTTP vulnerabilities
        /State:\s+VULNERABLE/i,                // State vulnerable
        /VULNERABLE/i,                         // General vulnerable mentions
        /\|\s+.*CVE-\d{4}-\d{4,}/,            // CVE in script output
        /\|\s+.*(?:exploit|attack|weakness)/i  // Other security terms
      ];
      
      const isVulnLine = vulnPatterns.some(pattern => pattern.test(trimmedLine));
      
      if (isVulnLine && currentHost) {
        console.log('Found vulnerability line:', trimmedLine);
        
        // Extract CVE if present
        const cveMatch = trimmedLine.match(/(CVE-\d{4}-\d{4,7})/);
        
        // Extract CVSS score if present
        const cvssMatch = trimmedLine.match(/(?:CVSS|Score)[:=]?\s*(\d+\.\d+)/i);
        
        // Determine severity
        let severity = 'unknown';
        const lowerLine = trimmedLine.toLowerCase();
        if (lowerLine.includes('critical')) severity = 'critical';
        else if (lowerLine.includes('high')) severity = 'high';
        else if (lowerLine.includes('medium')) severity = 'medium';
        else if (lowerLine.includes('low')) severity = 'low';
        else if (cvssMatch) {
          const cvssScore = parseFloat(cvssMatch[1]);
          if (cvssScore >= 9.0) severity = 'critical';
          else if (cvssScore >= 7.0) severity = 'high';
          else if (cvssScore >= 4.0) severity = 'medium';
          else severity = 'low';
        } else if (lowerLine.includes('vulnerable') || lowerLine.includes('exploit')) {
          severity = 'medium'; // Default for generic vulnerabilities
        }
        
        // Collect additional context from next few lines
        let description = trimmedLine;
        let additionalInfo = '';
        for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
          const nextLine = lines[j].trim();
          if (nextLine.startsWith('|') && 
              !nextLine.includes('vulners:') && 
              !nextLine.includes('CVE-') &&
              nextLine.length > 2) {
            additionalInfo += ' ' + nextLine.replace(/^\|\s*/, '');
          } else if (!nextLine.startsWith('|') && nextLine.length > 0) {
            break;
          }
        }
        
        if (additionalInfo.trim()) {
          description += ' ' + additionalInfo.trim();
        }
        
        const vulnerability = {
          host: currentHost,
          cve: cveMatch ? cveMatch[1] : `VULN-${vulnerabilities.length + 1}`,
          description: description.trim(),
          severity: severity,
          cvss: cvssMatch ? parseFloat(cvssMatch[1]) : null,
          status: 'open',
          service: currentService?.service || 'Unknown',
          port: currentService?.port || null,
          protocol: currentService?.protocol || 'tcp',
          discovered: new Date().toISOString()
        };
        
        vulnerabilities.push(vulnerability);
        console.log('Added vulnerability:', vulnerability);
      }
      
      // Parse the final summary line
      const summaryMatch = trimmedLine.match(/Nmap done: (\d+) IP addresses \((\d+) hosts up\) scanned/);
      if (summaryMatch) {
        const totalScanned = parseInt(summaryMatch[1]);
        hostsUp = parseInt(summaryMatch[2]);
        hostsDown = totalScanned - hostsUp;
        console.log(`Found summary: ${hostsUp} hosts up, ${hostsDown} hosts down out of ${totalScanned} scanned`);
      }
    }

    // If no summary found but we have scan reports, count them
    if (hostsUp === 0) {
      const scanReports = result.match(/Nmap scan report for/g);
      if (scanReports) {
        hostsUp = scanReports.length;
      }
    }

    const parsedResult = {
      hostsUp,
      hostsDown,
      openPorts,
      closedPorts,
      totalPorts: openPorts + closedPorts,
      services,
      vulnerabilities,
    };

    console.log('Final parsed result:', parsedResult);
    console.log('Total vulnerabilities found:', vulnerabilities.length);
    return parsedResult;
  }

  return { 
    hostsUp: 0, hostsDown: 0, openPorts: 0, closedPorts: 0, 
    totalPorts: 0, services: [], vulnerabilities: [] 
  };
};

  // Helper function to determine vulnerability severity
  const getSeverityFromLine = (line) => {
    const lowerLine = line.toLowerCase()
    if (lowerLine.includes('critical')) return 'critical'
    if (lowerLine.includes('high')) return 'high'
    if (lowerLine.includes('medium')) return 'medium'
    if (lowerLine.includes('low')) return 'low'
    if (lowerLine.includes('vulnerable')) return 'medium'
    return 'unknown'
  }

  // Helper function to calculate duration
  const calculateDuration = (startTime, endTime) => {
    if (!endTime || !startTime) return 'Unknown'
    
    try {
      const start = new Date(startTime)
      const end = new Date(endTime)
      const diff = end - start
      
      if (diff < 0) return 'Unknown'
      
      const minutes = Math.floor(diff / 60000)
      const seconds = Math.floor((diff % 60000) / 1000)
      
      return `${minutes}m ${seconds}s`
    } catch {
      return 'Unknown'
    }
  }

  const executeScan = async () => {
    const scanStartTime = new Date().toISOString()

    setIsScanning(true)
    setScanProgress(0)
    setScanStatus('Initializing scan...')
    setScanResults(null)

    const selectedType = scanTypes.find(type => type.value === scanConfig.scanType)

    try {
      let response

      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 90) return prev
          return prev + Math.random() * 10
        })
      }, 2000)

      // Update status messages
      setTimeout(() => setScanStatus('Connecting to target...'), 1000)
      setTimeout(() => setScanStatus('Scanning ports...'), 3000)
      setTimeout(() => setScanStatus('Analyzing services...'), 5000)
      
      // Add script-specific status
      if (scanConfig.useScripts || scanConfig.scanType === 'script') {
        setTimeout(() => setScanStatus('Running vulnerability scripts...'), 7000)
      }

      switch (scanConfig.scanType) {
        case 'quick':
          // Enhanced quick scan with script support
          response = await axios.get(`${API_BASE}/scan`, {
            params: {
              target: scanConfig.target,
              ports: '22,80,443',
              aggressive: false,
              scripts: scanConfig.useScripts
            }
          })
          break

        case 'full':
          // Enhanced full scan with script support
          response = await axios.get(`${API_BASE}/scan`, {
            params: {
              target: scanConfig.target,
              ports: '1-1000',
              aggressive: false,
              scripts: scanConfig.useScripts
            }
          })
          break

        case 'script':
          // Dedicated vulnerability scan
          response = await axios.get(`${API_BASE}/script-scan`)
          break

        case 'aggressive':
          const target = scanConfig.target || ''
          response = await axios.get(`${API_BASE}/aggressive-scan`, {
            params: { target },
          })
          break

        case 'custom':
          response = await axios.get(`${API_BASE}/scan`, {
            params: {
              target: scanConfig.target,
              ports: scanConfig.ports,
              aggressive: false,
              scripts: scanConfig.useScripts
            }
          })
          break

        case 'stealth':
          response = await axios.get(`${API_BASE}/scan`, {
            params: {
              target: scanConfig.target,
              ports: scanConfig.ports,
              aggressive: false,
              scripts: scanConfig.useScripts,
            },
          })
          break

        default:
          response = await axios.get(`${API_BASE}/scan`, {
            params: {
              target: scanConfig.target,
              ports: scanConfig.ports,
              aggressive: scanConfig.scanType === 'aggressive',
              scripts: scanConfig.useScripts,
            },
          })
      }

      clearInterval(progressInterval)
      setScanProgress(100)
      setScanStatus('Scan completed successfully')
      setScanResults(response.data)

      // Enhanced result parsing and saving
      const parsedResults = parseScanResults(response.data.result)
      
      const scanHistoryData = {
        id: Date.now(),
        type: scanConfig.scanType,
        target: scanConfig.target || response.data.target || response.data.subnet,
        status: 'completed',
        startTime: scanStartTime,
        endTime: new Date().toISOString(),
        ports: scanConfig.scanType === 'script' ? '22,80,443' : 
               scanConfig.scanType === 'full' ? '1-1000' :
               scanConfig.scanType === 'quick' ? '22,80,443' :
               scanConfig.ports,
        useScripts: scanConfig.useScripts || scanConfig.scanType === 'script' || scanConfig.scanType === 'aggressive',
        result: response.data.result,
        devicesFound: parsedResults.hostsUp,
        hostsUp: parsedResults.hostsUp,
        hostsDown: parsedResults.hostsDown,
        openPorts: parsedResults.openPorts,
        closedPorts: parsedResults.closedPorts,
        totalPorts: parsedResults.totalPorts,
        services: parsedResults.services,
        vulnerabilities: parsedResults.vulnerabilities.length,
        vulnerabilityDetails: parsedResults.vulnerabilities,
        duration: calculateDuration(scanStartTime, new Date().toISOString()),
        apiResponse: response.data,
        timestamp: new Date().toISOString(),
        // Add raw scan output for debugging
        rawOutput: response.data.result
      }

      console.log('Saving scan with parsed results:', scanHistoryData)
      
      // Save to localStorage directly
      try {
        const existingHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]')
        const updatedHistory = [scanHistoryData, ...existingHistory].slice(0, 100)
        localStorage.setItem('scanHistory', JSON.stringify(updatedHistory))
        console.log('Scan saved to localStorage successfully')
      } catch (storageError) {
        console.error('Failed to save to localStorage:', storageError)
      }
      
      // Also try to save via global function if available
      if (window.saveScanToHistory) {
        window.saveScanToHistory(scanHistoryData)
      }
      
      // Try to save to backend
      try {
        await axios.post(`${API_BASE}/save-scan-history`, scanHistoryData)
        console.log('Scan saved to backend successfully')
      } catch (backendError) {
        console.warn('Could not save scan to backend:', backendError.message)
      }

    } catch (error) {
      console.error('Scan failed:', error)
      const errorMessage = error.response?.data?.detail || error.message
      setScanStatus('Scan failed: ' + errorMessage)
      setScanResults({ error: errorMessage })

      // Save failed scan to history
      const failedScanData = {
        id: Date.now(),
        type: scanConfig.scanType,
        target: scanConfig.target,
        status: 'failed',
        startTime: scanStartTime,
        endTime: new Date().toISOString(),
        ports: scanConfig.ports,
        useScripts: scanConfig.useScripts,
        error: errorMessage,
        devicesFound: 0,
        hostsUp: 0,
        hostsDown: 0,
        openPorts: 0,
        closedPorts: 0,
        totalPorts: 0,
        services: [],
        vulnerabilities: 0,
        vulnerabilityDetails: [],
        duration: calculateDuration(scanStartTime, new Date().toISOString()),
        timestamp: new Date().toISOString()
      }
      
      // Save failed scan to localStorage
      try {
        const existingHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]')
        const updatedHistory = [failedScanData, ...existingHistory].slice(0, 100)
        localStorage.setItem('scanHistory', JSON.stringify(updatedHistory))
      } catch (storageError) {
        console.error('Failed to save failed scan to localStorage:', storageError)
      }
      
      if (window.saveScanToHistory) {
        window.saveScanToHistory(failedScanData)
      }
    } finally {
      setIsScanning(false)
    }
  }

  const handleStartScan = () => {
    executeScan()
  }

  const handleStopScan = () => {
    setIsScanning(false)
    setScanProgress(0)
    setScanStatus('Scan stopped by user')
  }

  const selectedScanType = scanTypes.find(type => type.value === scanConfig.scanType)

  // Update ports when scan type changes
  useEffect(() => {
    if (selectedScanType) {
      setScanConfig(prev => ({
        ...prev,
        ports: selectedScanType.defaultPorts
      }))
    }
  }, [scanConfig.scanType])

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Scan Configuration</h1>
          <p className="text-muted-foreground">Configure and execute network security scans</p>
        </div>
        <div className="flex space-x-2">
          {isScanning ? (
            <Button 
              onClick={handleStopScan} 
              variant="destructive" 
              className="btn-destructive-click"
            >
              <Square className="w-4 h-4 mr-2" />
              Stop Scan
            </Button>
          ) : (
            <Button 
              onClick={handleStartScan} 
              className="btn-primary-click"
              disabled={!scanConfig.target}
            >
              <Play className="w-4 h-4 mr-2" />
              Start Scan
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan Configuration */}
        <div className="lg:col-span-2 space-y-6">
          {/* Network Detection */}
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-card-foreground">
                <Network className="w-5 h-5" />
                <span>Network Detection</span>
              </CardTitle>
              <CardDescription>
                Automatically detected network configuration
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm font-medium text-muted-foreground">Local IP</Label>
                  <p className="font-mono text-sm text-card-foreground">{networkInfo.ip}</p>
                </div>
                <div>
                  <Label className="text-sm font-medium text-muted-foreground">Subnet</Label>
                  <p className="font-mono text-sm text-card-foreground">{networkInfo.subnet}</p>
                </div>
                <div>
                  <Label className="text-sm font-medium text-muted-foreground">Netmask</Label>
                  <p className="font-mono text-sm text-card-foreground">{networkInfo.netmask}</p>
                </div>
                <div>
                  <Label className="text-sm font-medium text-muted-foreground">Interface</Label>
                  <p className="font-mono text-sm text-card-foreground">{networkInfo.interface}</p>
                </div>
              </div>
              <Button 
                variant="outline" 
                className="w-full btn-outline-click"
                onClick={fetchNetworkInfo}
                disabled={isDetecting}
              >
                {isDetecting ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Detecting...
                  </>
                ) : (
                  'Re-detect Network'
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Scan Parameters */}
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-card-foreground">
                <Settings className="w-5 h-5" />
                <span>Scan Parameters</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Target */}
              <div className="space-y-2">
                <Label htmlFor="target" className="text-card-foreground">Target</Label>
                <Input
                  id="target"
                  placeholder="192.168.1.0/24 or 192.168.1.1-100"
                  value={scanConfig.target}
                  onChange={(e) => setScanConfig(prev => ({ ...prev, target: e.target.value }))}
                  className="bg-input border-border text-foreground"
                />
                <p className="text-xs text-muted-foreground">
                  Enter IP address, subnet (CIDR), or IP range
                </p>
              </div>

              {/* Scan Type */}
              <div className="space-y-2">
                <Label htmlFor="scan-type" className="text-card-foreground">Scan Type</Label>
                <Select 
                  value={scanConfig.scanType} 
                  onValueChange={(value) => setScanConfig(prev => ({ ...prev, scanType: value }))}
                >
                  <SelectTrigger className="bg-input border-border text-foreground">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-popover border-border">
                    {scanTypes.map(type => {
                      const Icon = type.icon
                      return (
                        <SelectItem key={type.value} value={type.value} className="text-popover-foreground">
                          <div className="flex items-center space-x-3">
                            <Icon className={`w-4 h-4 ${type.color}`} />
                            <div>
                              <div className="font-medium">{type.label}</div>
                              <div className="text-xs text-muted-foreground">{type.description}</div>
                            </div>
                          </div>
                        </SelectItem>
                      )
                    })}
                  </SelectContent>
                </Select>
                
                {selectedScanType && (
                  <div className="flex items-center space-x-2 p-3 bg-muted/50 rounded-lg">
                    <selectedScanType.icon className={`w-4 h-4 ${selectedScanType.color}`} />
                    <div className="flex-1">
                      <p className="text-sm font-medium text-card-foreground">{selectedScanType.label}</p>
                      <p className="text-xs text-muted-foreground">{selectedScanType.description}</p>
                      <div className="flex items-center space-x-4 mt-1 text-xs">
                        <span className="text-muted-foreground">
                          Ports: <span className="font-mono">{selectedScanType.defaultPorts}</span>
                        </span>
                        {selectedScanType.supportsScripts && (
                          <div className="flex items-center space-x-1">
                            <Shield className="w-3 h-3" />
                            <span className="text-muted-foreground">Script support</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Ports - Only show for certain scan types */}
              {selectedScanType?.supportsPorts && (
                <div className="space-y-2">
                  <Label htmlFor="ports" className="text-card-foreground">Ports</Label>
                  <Select 
                    value={scanConfig.ports} 
                    onValueChange={(value) => setScanConfig(prev => ({ ...prev, ports: value }))}
                  >
                    <SelectTrigger className="bg-input border-border text-foreground">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-popover border-border">
                      {commonPorts.map(port => (
                        <SelectItem key={port.value} value={port.value} className="text-popover-foreground">
                          {port.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Input
                    placeholder="Custom ports (e.g., 80,443,8080)"
                    value={scanConfig.ports}
                    onChange={(e) => setScanConfig(prev => ({ ...prev, ports: e.target.value }))}
                    className="bg-input border-border text-foreground"
                  />
                </div>
              )}

              {/* Advanced Options */}
              <div className="space-y-4">
                {/* Vulnerability Scripts Option */}
                {selectedScanType?.supportsScripts && selectedScanType.value !== 'script' && (
                  <div className="space-y-3">
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="use-scripts"
                        checked={scanConfig.useScripts}
                        onCheckedChange={(checked) => setScanConfig(prev => ({ ...prev, useScripts: checked }))}
                      />
                      <Label htmlFor="use-scripts" className="text-sm text-card-foreground">
                        Enable vulnerability scripts
                      </Label>
                      <Shield className="w-4 h-4 text-yellow-500" />
                    </div>
                    
                    {scanConfig.useScripts && (
                      <div className="bg-yellow-50 dark:bg-yellow-900/10 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3">
                        <div className="flex items-start space-x-2">
                          <Info className="w-4 h-4 text-yellow-600 mt-0.5 flex-shrink-0" />
                          <div className="text-sm">
                            <p className="text-yellow-800 dark:text-yellow-200 font-medium mb-1">
                              Vulnerability Scripts Enabled
                            </p>
                            <p className="text-yellow-700 dark:text-yellow-300 text-xs">
                              This will run Nmap's vulnerability detection scripts (--script vuln) which can:
                            </p>
                            <ul className="text-yellow-700 dark:text-yellow-300 text-xs mt-1 ml-4 list-disc">
                              <li>Detect common vulnerabilities and misconfigurations</li>
                              <li>Check for CVE-based security issues</li>
                              <li>Significantly increase scan time (2-5x longer)</li>
                              <li>May trigger security alerts on target systems</li>
                            </ul>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Script scan information */}
                {selectedScanType?.value === 'script' && (
                  <div className="bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                    <div className="flex items-start space-x-2">
                      <Shield className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
                      <div className="text-sm">
                        <p className="text-blue-800 dark:text-blue-200 font-medium mb-1">
                          Dedicated Vulnerability Scan
                        </p>
                        <p className="text-blue-700 dark:text-blue-300 text-xs">
                          This scan type automatically enables vulnerability scripts and focuses on security assessment.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Aggressive scan information */}
                {selectedScanType?.value === 'aggressive' && (
                  <div className="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-3">
                    <div className="flex items-start space-x-2">
                                              <Activity className="w-4 h-4 text-red-600 mt-0.5 flex-shrink-0" />
                      <div className="text-sm">
                        <p className="text-red-800 dark:text-red-200 font-medium mb-1">
                          Aggressive Scan Mode
                        </p>
                        <p className="text-red-700 dark:text-red-300 text-xs">
                          Includes OS detection, version scanning, script scanning, and traceroute. Very detectable by security systems.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                <div className="space-y-2">
                  <Label htmlFor="timeout" className="text-card-foreground">Timeout (seconds)</Label>
                  <Input
                    id="timeout"
                    type="number"
                    min="60"
                    max="3600"
                    value={scanConfig.timeout}
                    onChange={(e) => setScanConfig(prev => ({ ...prev, timeout: parseInt(e.target.value) }))}
                    className="bg-input border-border text-foreground"
                  />
                  <p className="text-xs text-muted-foreground">
                    {scanConfig.useScripts || scanConfig.scanType === 'script' ? 
                      'Vulnerability scans may need longer timeouts (recommended: 600+ seconds)' :
                      'Standard scans typically complete within 60-300 seconds'
                    }
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Scan Status */}
        <div className="space-y-6">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-card-foreground">
                <Activity className="w-5 h-5" />
                <span>Scan Status</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isScanning ? (
                <div className="space-y-4">
                  <div className="flex items-center space-x-2">
                    <div className="w-3 h-3 bg-blue-500 rounded-full animate-pulse"></div>
                    <span className="font-medium text-card-foreground">Scanning in progress</span>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-card-foreground">Progress</span>
                      <span className="text-card-foreground">{Math.round(scanProgress)}%</span>
                    </div>
                    <Progress value={scanProgress} className="h-2" />
                  </div>

                  <div className="space-y-2 text-sm">
                    <p className="text-muted-foreground">{scanStatus}</p>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Target:</span>
                      <span className="text-card-foreground font-mono">{scanConfig.target}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Type:</span>
                      <Badge variant="secondary" className="bg-secondary text-secondary-foreground">
                        {selectedScanType?.label}
                      </Badge>
                    </div>
                    {(scanConfig.useScripts || scanConfig.scanType === 'script' || scanConfig.scanType === 'aggressive') && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Scripts:</span>
                        <Badge variant="secondary" className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400">
                          <Shield className="w-3 h-3 mr-1" />
                          Enabled
                        </Badge>
                      </div>
                    )}
                  </div>
                </div>
              ) : scanResults ? (
                <div className="space-y-4">
                  <div className="flex items-center space-x-2">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    <span className="font-medium text-card-foreground">Scan Completed</span>
                  </div>
                  
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Type:</span>
                      <Badge variant="secondary" className="bg-secondary text-secondary-foreground">
                        {scanResults.type || selectedScanType?.label}
                      </Badge>
                    </div>
                    {scanResults.subnet && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Subnet:</span>
                        <span className="text-card-foreground font-mono">{scanResults.subnet}</span>
                      </div>
                    )}
                    {scanResults.target && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Target:</span>
                        <span className="text-card-foreground font-mono">{scanResults.target}</span>
                      </div>
                    )}
                    
                    {/* Show parsed results if available */}
                    {scanResults.result && (
                      <div className="mt-4 p-3 bg-muted/30 rounded-lg">
                        <h5 className="font-medium text-card-foreground mb-2">Quick Results:</h5>
                        {(() => {
                          const parsed = parseScanResults(scanResults.result)
                          return (
                            <div className="grid grid-cols-2 gap-2 text-xs">
                              <div>Devices Found: <span className="font-bold text-green-600">{parsed.hostsUp}</span></div>
                              <div>Open Ports: <span className="font-bold text-blue-600">{parsed.openPorts}</span></div>
                              <div>Services: <span className="font-bold text-purple-600">{parsed.services.length}</span></div>
                              <div>Vulnerabilities: <span className="font-bold text-red-600">{parsed.vulnerabilities.length}</span></div>
                            </div>
                          )
                        })()}
                      </div>
                    )}
                  </div>
                  
                  <Button 
                    variant="outline" 
                    className="w-full btn-outline-click text-xs"
                    onClick={() => {
                      console.log('Full results:', scanResults)
                    }}
                  >
                    View Full Results
                  </Button>
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Clock className="w-12 h-12 mx-auto mb-4 text-muted-foreground/50" />
                  <p>No active scan</p>
                  <p className="text-sm">Configure and start a scan to monitor progress</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Scan Tips */}
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-card-foreground">Scan Tips</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                <p className="text-card-foreground">Quick scans are faster but may miss some services</p>
              </div>
              <div className="flex items-start space-x-2">
                <Shield className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0" />
                <p className="text-card-foreground">Enable vulnerability scripts for security assessment</p>
              </div>
              <div className="flex items-start space-x-2">
                <AlertCircle className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0" />
                <p className="text-card-foreground">Script scans take significantly longer to complete</p>
              </div>
              <div className="flex items-start space-x-2">
                <AlertCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                <p className="text-card-foreground">Only scan networks you own or have permission to test</p>
              </div>
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-card-foreground">Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Button 
                variant="outline" 
                className="w-full justify-start btn-outline-click"
                onClick={() => setScanConfig(prev => ({ ...prev, scanType: 'quick', ports: '22,80,443', useScripts: false }))}
              >
                <Zap className="w-4 h-4 mr-2 text-blue-500" />
                Quick Web Scan
              </Button>
              <Button 
                variant="outline" 
                className="w-full justify-start btn-outline-click"
                onClick={() => setScanConfig(prev => ({ ...prev, scanType: 'full', ports: '1-1000', useScripts: false }))}
              >
                <Target className="w-4 h-4 mr-2 text-green-500" />
                Full Port Scan
              </Button>
              <Button 
                variant="outline" 
                className="w-full justify-start btn-outline-click"
                onClick={() => setScanConfig(prev => ({ ...prev, scanType: 'stealth', useScripts: true }))}
              >
                <Eye className="w-4 h-4 mr-2 text-purple-500" />
                Stealth + Vulns
              </Button>
              <Button 
                variant="outline" 
                className="w-full justify-start btn-outline-click"
                onClick={() => setScanConfig(prev => ({ ...prev, scanType: 'script', useScripts: true }))}
              >
                <Shield className="w-4 h-4 mr-2 text-yellow-500" />
                Vulnerability Scan
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

export default ScanConfiguration
