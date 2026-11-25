import { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  History, Activity, Clock, CheckCircle, XCircle, AlertTriangle, Eye, Download, Calendar, 
  Target, Shield, Monitor, Zap, Search, RefreshCw, Loader2, Terminal, FileText, Trash2 
} from 'lucide-react';

const ScanHistory = () => {
  const [scanHistory, setScanHistory] = useState([]);
  const [filteredHistory, setFilteredHistory] = useState([]);
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedScan, setSelectedScan] = useState(null);
  const [showDetailsDialog, setShowDetailsDialog] = useState(false);

  const API_BASE = 'http://127.0.0.1:8000';

  // Enhanced scan result parser - matches the one in ScanConfiguration
  const parseScanResults = (result) => {
    console.log('Parsing scan result:', result);
    
    if (!result) return { 
      hostsUp: 0, hostsDown: 0, openPorts: 0, closedPorts: 0, 
      totalPorts: 0, services: [], vulnerabilities: [] 
    };

    // If result is already parsed object, return it directly or extract values
    if (typeof result === 'object' && !Array.isArray(result)) {
      return {
        hostsUp: result.hostsUp || result.hosts_up || 0,
        hostsDown: result.hostsDown || result.hosts_down || 0,
        openPorts: result.openPorts?.length || result.open_ports?.length || result.openPorts || 0,
        closedPorts: result.closedPorts?.length || result.closed_ports?.length || result.closedPorts || 0,
        totalPorts: (result.openPorts?.length || result.openPorts || 0) + (result.closedPorts?.length || result.closedPorts || 0),
        services: result.services || [],
        vulnerabilities: result.vulnerabilities || [],
      };
    }

    // Parse raw nmap string output
    if (typeof result === 'string') {
      try {
        const lines = result.split('\n');
        let hostsUp = 0;
        let hostsDown = 0;
        let openPorts = 0;
        let closedPorts = 0;
        let services = [];
        let vulnerabilities = [];
        let currentHost = null;

        for (const line of lines) {
          const trimmedLine = line.trim();
          
          // Extract current host being scanned
          if (trimmedLine.includes('Nmap scan report for')) {
            const hostMatch = trimmedLine.match(/Nmap scan report for (.+)/);
            if (hostMatch) {
              currentHost = hostMatch[1];
            }
          }
          
          // Count open ports and extract services
          if (trimmedLine.match(/^\d+\/\w+\s+open/)) {
            openPorts++;
            const portMatch = trimmedLine.match(/^(\d+\/\w+)\s+open\s+(.+)/);
            if (portMatch) {
              services.push({
                host: currentHost || 'Unknown',
                port: portMatch[1],
                service: portMatch[2].trim(),
                state: 'open'
              });
            }
          }
          
          // Count closed ports
          if (trimmedLine.match(/^\d+\/\w+\s+closed/)) {
            closedPorts++;
          }
          
          // Look for vulnerabilities
          if (trimmedLine.includes('VULNERABLE') || trimmedLine.includes('CVE-')) {
            vulnerabilities.push({
              host: currentHost || 'Unknown',
              description: trimmedLine,
              severity: 'unknown'
            });
          }
          
          // Parse the final summary line - this is the most reliable count
          const summaryMatch = trimmedLine.match(/Nmap done: (\d+) IP addresses \((\d+) hosts up\) scanned/);
          if (summaryMatch) {
            const totalScanned = parseInt(summaryMatch[1]);
            hostsUp = parseInt(summaryMatch[2]);
            hostsDown = totalScanned - hostsUp;
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

        console.log('Parsed nmap result:', parsedResult);
        return parsedResult;
        
      } catch (error) {
        console.error('Error parsing scan results:', error);
        return { hostsUp: 0, hostsDown: 0, openPorts: 0, closedPorts: 0, totalPorts: 0, services: [], vulnerabilities: [] };
      }
    }

    return { hostsUp: 0, hostsDown: 0, openPorts: 0, closedPorts: 0, totalPorts: 0, services: [], vulnerabilities: [] };
  };

  const fetchScanHistory = async () => {
    setRefreshing(true);
    try {
      console.log('Fetching scan history...');
      
      // Load from localStorage first
      let localHistory = [];
      try {
        const savedHistory = localStorage.getItem('scanHistory');
        if (savedHistory) {
          localHistory = JSON.parse(savedHistory);
          console.log('Loaded from localStorage:', localHistory.length, 'scans');
          
          // Process each scan to ensure it has parsed results
          localHistory = localHistory.map(scan => {
            if (!scan.hostsUp && scan.result) {
              const parsed = parseScanResults(scan.result);
              return {
                ...scan,
                hostsUp: parsed.hostsUp,
                hostsDown: parsed.hostsDown,
                openPorts: parsed.openPorts,
                closedPorts: parsed.closedPorts,
                totalPorts: parsed.totalPorts,
                services: parsed.services,
                vulnerabilityDetails: parsed.vulnerabilities,
                vulnerabilities: parsed.vulnerabilities.length
              };
            }
            return scan;
          });
        }
      } catch (parseError) {
        console.error('Error parsing localStorage data:', parseError);
        localStorage.removeItem('scanHistory');
      }

      // Set the history from localStorage only - don't merge with backend
      setScanHistory(localHistory);
      setFilteredHistory(localHistory);
      
    } catch (error) {
      console.error('Error fetching scan history:', error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const saveScanToHistory = (scanData) => {
    console.log('Saving scan to history:', scanData);
    
    const newScan = {
      id: scanData.id || Date.now(),
      type: scanData.type || 'unknown',
      target: scanData.target || 'unknown',
      status: scanData.status || 'completed',
      startTime: scanData.startTime || new Date().toISOString(),
      endTime: scanData.endTime || new Date().toISOString(),
      ports: scanData.ports || 'default',
      useScripts: scanData.useScripts || false,
      result: scanData.result || '',
      devicesFound: scanData.devicesFound || scanData.hostsUp || 0,
      hostsUp: scanData.hostsUp || scanData.devicesFound || 0,
      hostsDown: scanData.hostsDown || 0,
      openPorts: scanData.openPorts || 0,
      closedPorts: scanData.closedPorts || 0,
      totalPorts: scanData.totalPorts || 0,
      services: scanData.services || [],
      vulnerabilities: scanData.vulnerabilities || 0,
      vulnerabilityDetails: scanData.vulnerabilityDetails || [],
      duration: scanData.duration || 'Unknown',
      error: scanData.error || null,
      timestamp: scanData.timestamp || new Date().toISOString(),
      rawOutput: scanData.rawOutput || scanData.result,
      ...scanData,
    };

    const updatedHistory = [newScan, ...scanHistory].slice(0, 100);
    setScanHistory(updatedHistory);
    setFilteredHistory(updatedHistory);
    
    try {
      localStorage.setItem('scanHistory', JSON.stringify(updatedHistory));
      console.log('Scan saved to localStorage successfully');
    } catch (storageError) {
      console.error('Failed to save to localStorage:', storageError);
    }
    
    saveScanToBackend(newScan);
  };

  const saveScanToBackend = async (scanData) => {
    try {
      await axios.post(`${API_BASE}/save-scan-history`, scanData);
      console.log('Scan saved to backend successfully');
    } catch (error) {
      console.warn('Could not save scan to backend:', error.message);
    }
  };

  const clearHistory = () => {
    if (window.confirm('Are you sure you want to clear all scan history? This action cannot be undone.')) {
      setScanHistory([]);
      setFilteredHistory([]);
      localStorage.removeItem('scanHistory');
      
      // Also clear backend history
      try {
        axios.delete(`${API_BASE}/scan-history`);
        console.log('Backend history cleared');
      } catch (error) {
        console.warn('Could not clear backend history:', error.message);
      }
      
      console.log('Scan history cleared');
    }
  };

  const deleteScan = async (scanId) => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      const updatedHistory = scanHistory.filter(scan => scan.id !== scanId);
      setScanHistory(updatedHistory);
      setFilteredHistory(updatedHistory);
      localStorage.setItem('scanHistory', JSON.stringify(updatedHistory));
      
      // Also delete from backend
      try {
        await axios.delete(`${API_BASE}/scan-history/${scanId}`);
        console.log('Scan deleted from backend');
      } catch (error) {
        console.warn('Could not delete scan from backend:', error.message);
      }
      
      console.log('Scan deleted:', scanId);
    }
  };

  useEffect(() => {
    fetchScanHistory();
  }, []);

  const filteredHistoryMemo = useMemo(() => {
    let filtered = scanHistory;

    if (typeFilter !== 'all') {
      filtered = filtered.filter(scan => scan.type === typeFilter);
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter(scan => scan.status === statusFilter);
    }

    return filtered;
  }, [scanHistory, typeFilter, statusFilter]);

  useEffect(() => {
    setFilteredHistory(filteredHistoryMemo);
  }, [filteredHistoryMemo]);

  useEffect(() => {
    window.saveScanToHistory = saveScanToHistory;
    console.log('Global saveScanToHistory function registered');
    
    return () => {
      delete window.saveScanToHistory;
    };
  }, [scanHistory]);

const getScanTypeIcon = (type) => {
  switch (type) {
    case 'quick': return <Zap className="w-4 h-4 text-blue-500" />;
    case 'full': return <Target className="w-4 h-4 text-green-500" />;
    case 'stealth': return <Eye className="w-4 h-4 text-purple-500" />;
    case 'aggressive': return <Activity className="w-4 h-4 text-red-500" />;
    case 'custom': return <Search className="w-4 h-4 text-orange-500" />;
    case 'script': return <Shield className="w-4 h-4 text-yellow-500" />; // Add this line
    default: return <Activity className="w-4 h-4 text-gray-500" />;
  }
};

const getScanTypeColor = (type) => {
  switch (type) {
    case 'quick': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
    case 'full': return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400';
    case 'stealth': return 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-400';
    case 'aggressive': return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
    case 'custom': return 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400';
    case 'script': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400'; // Add this line
    default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400';
  }
};

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed': return <XCircle className="w-4 h-4 text-red-500" />;
      case 'running': return <Activity className="w-4 h-4 text-blue-500 animate-spin" />;
      default: return <Clock className="w-4 h-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400';
      case 'failed': return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
      case 'running': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400';
    }
  };

  const formatDateTime = (dateTime) => {
    try {
      const date = new Date(dateTime);
      return date.toLocaleString();
    } catch {
      return 'Invalid date';
    }
  };

  const calculateDuration = (startTime, endTime) => {
    if (!endTime || !startTime) return 'Unknown';
    
    try {
      const start = new Date(startTime);
      const end = new Date(endTime);
      const diff = end - start;
      
      if (diff < 0) return 'Unknown';
      
      const minutes = Math.floor(diff / 60000);
      const seconds = Math.floor((diff % 60000) / 1000);
      
      return `${minutes}m ${seconds}s`;
    } catch {
      return 'Unknown';
    }
  };

  const exportHistory = () => {
    const dataStr = JSON.stringify(scanHistory, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
    const exportFileDefaultName = `scan-history-${new Date().toISOString().split('T')[0]}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const exportScanDetails = (scan) => {
    const exportData = { ...scan, exportedAt: new Date().toISOString() };
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
    const exportFileDefaultName = `scan-${scan.id}-${scan.type}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const showScanDetails = (scan) => {
    setSelectedScan(scan);
    setShowDetailsDialog(true);
  };

  // Calculate statistics from the LATEST scan only, not all scans
  const latestScan = scanHistory.length > 0 ? scanHistory[0] : null;
  const totalScans = scanHistory.length;
  const completedScans = scanHistory.filter(s => s.status === 'completed').length;
  const failedScans = scanHistory.filter(s => s.status === 'failed').length;
  
  // Use latest scan data for current results
  const currentDevices = latestScan ? (latestScan.hostsUp || latestScan.devicesFound || 0) : 0;
  const currentVulnerabilities = latestScan ? (latestScan.vulnerabilities || 0) : 0;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Scan History</h1>
          <p className="text-muted-foreground">Historical record of all network security scans</p>
        </div>
        <div className="flex space-x-2">
          <Button 
            variant="outline" 
            onClick={fetchScanHistory}
            disabled={refreshing}
            className="btn-outline-click"
          >
            {refreshing ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4 mr-2" />
            )}
            Refresh
          </Button>
          {scanHistory.length > 0 && (
            <>
              <Button 
                variant="outline" 
                onClick={clearHistory}
                className="btn-outline-click text-red-600 hover:text-red-700"
              >
                <Trash2 className="w-4 h-4 mr-2" />
                Clear History
              </Button>
              <Button onClick={exportHistory} className="btn-primary-click">
                <Download className="w-4 h-4 mr-2" />
                Export History
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Statistics Cards - Now showing latest scan results */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Activity className="w-5 h-5 text-blue-500" />
              <div>
                <p className="text-sm font-medium text-card-foreground">Total Scans</p>
                <p className="text-2xl font-bold text-card-foreground">{totalScans}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <CheckCircle className="w-5 h-5 text-green-500" />
              <div>
                <p className="text-sm font-medium text-card-foreground">Completed</p>
                <p className="text-2xl font-bold text-card-foreground">{completedScans}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <XCircle className="w-5 h-5 text-red-500" />
              <div>
                <p className="text-sm font-medium text-card-foreground">Failed</p>
                <p className="text-2xl font-bold text-card-foreground">{failedScans}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Monitor className="w-5 h-5 text-purple-500" />
              <div>
                <p className="text-sm font-medium text-card-foreground">Latest Scan Devices</p>
                <p className="text-2xl font-bold text-card-foreground">{currentDevices}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-red-500" />
              <div>
                <p className="text-sm font-medium text-card-foreground">Latest Scan Vulnerabilities</p>
                <p className="text-2xl font-bold text-card-foreground">{currentVulnerabilities}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Latest Scan Summary */}
      {latestScan && (
        <Card className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/10 dark:to-purple-900/10 border-blue-200 dark:border-blue-800">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2 text-card-foreground">
              <Activity className="w-5 h-5 text-blue-500" />
              <span>Latest Scan Results</span>
              <Badge className={getScanTypeColor(latestScan.type)}>
                {latestScan.type}
              </Badge>
            </CardTitle>
            <CardDescription>
              {formatDateTime(latestScan.startTime || latestScan.timestamp)} - Target: {latestScan.target}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">{latestScan.hostsUp || 0}</div>
                <div className="text-sm text-muted-foreground">Hosts Up</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">{latestScan.openPorts || 0}</div>
                <div className="text-sm text-muted-foreground">Open Ports</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-600">{latestScan.services?.length || 0}</div>
                <div className="text-sm text-muted-foreground">Services</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">{latestScan.vulnerabilities || 0}</div>
                <div className="text-sm text-muted-foreground">Vulnerabilities</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filter Controls */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2 text-card-foreground">
            <History className="w-5 h-5" />
            <span>Filter Scans</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="bg-input border-border text-foreground">
                <SelectValue placeholder="All Scan Types" />
              </SelectTrigger>
              <SelectContent className="bg-popover border-border">
                <SelectItem value="all" className="text-popover-foreground">All Scan Types</SelectItem>
                <SelectItem value="quick" className="text-popover-foreground">Quick Scan</SelectItem>
                <SelectItem value="full" className="text-popover-foreground">Full Scan</SelectItem>
                <SelectItem value="stealth" className="text-popover-foreground">Stealth Scan</SelectItem>
                <SelectItem value="aggressive" className="text-popover-foreground">Aggressive Scan</SelectItem>
                <SelectItem value="custom" className="text-popover-foreground">Custom Scan</SelectItem>
                <SelectItem value="script" className="text-popover-foreground">Vulnerability Scan</SelectItem> {/* Add this line */}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="bg-input border-border text-foreground">
                <SelectValue placeholder="All Status" />
              </SelectTrigger>
              <SelectContent className="bg-popover border-border">
                <SelectItem value="all" className="text-popover-foreground">All Status</SelectItem>
                <SelectItem value="completed" className="text-popover-foreground">Completed</SelectItem>
                <SelectItem value="running" className="text-popover-foreground">Running</SelectItem>
                <SelectItem value="failed" className="text-popover-foreground">Failed</SelectItem>
              </SelectContent>
            </Select>
            <div className="text-sm text-muted-foreground flex items-center">
              Showing {filteredHistory.length} of {scanHistory.length} scans
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Scan Timeline */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-card-foreground">Scan Timeline</CardTitle>
          <CardDescription>Chronological list of all network scans with detailed results</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="text-center">
                <Loader2 className="w-12 h-12 mx-auto mb-4 text-muted-foreground animate-spin" />
                <p className="text-muted-foreground">Loading scan history...</p>
              </div>
            </div>
          ) : filteredHistory.length === 0 ? (
            <div className="text-center py-12">
              <History className="w-12 h-12 mx-auto mb-4 text-muted-foreground/50" />
              <p className="text-muted-foreground">No scans found matching your criteria</p>
              <p className="text-sm text-muted-foreground">
                {scanHistory.length === 0 
                  ? "Start your first scan to see history here" 
                  : "Try adjusting your filters"}
              </p>
            </div>
          ) : (
            <ScrollArea className="h-[600px] pr-4">
              <div className="space-y-6">
                {filteredHistory.map((scan, index) => {
                  // Use stored parsed results or parse on demand
                  const parsedResults = scan.hostsUp !== undefined ? scan : parseScanResults(scan.result);
                  const duration = scan.duration || calculateDuration(scan.startTime, scan.endTime);
                  
                  return (
                    <div key={scan.id} className="relative">
                      {index < filteredHistory.length - 1 && (
                        <div className="absolute left-6 top-12 w-0.5 h-16 bg-border"></div>
                      )}
                      <div className="flex items-start space-x-4">
                        <div className="flex-shrink-0 w-12 h-12 bg-primary rounded-full flex items-center justify-center">
                          {getScanTypeIcon(scan.type)}
                        </div>
                        <div className="flex-1 border border-border rounded-lg p-6 hover:bg-muted/10 transition-colors">
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center space-x-3">
                              <h3 className="font-semibold text-card-foreground">
                                {scan.type ? scan.type.charAt(0).toUpperCase() + scan.type.slice(1) : 'Unknown'} Scan
                              </h3>
                              <Badge className={getScanTypeColor(scan.type)}>
                                {scan.type || 'unknown'}
                              </Badge>
                              <Badge className={getStatusColor(scan.status)}>
                                <div className="flex items-center space-x-1">
                                  {getStatusIcon(scan.status)}
                                  <span>{scan.status}</span>
                                </div>
                              </Badge>
                            </div>
                            <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                              <Calendar className="w-4 h-4" />
                              <span>{formatDateTime(scan.startTime || scan.timestamp)}</span>
                            </div>
                          </div>
                          
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4 text-sm">
                            <div>
                              <span className="text-muted-foreground">Target:</span>
                              <p className="text-card-foreground font-mono break-all">{scan.target}</p>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Duration:</span>
                              <p className="text-card-foreground">{duration}</p>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Devices Found:</span>
                              <p className="text-green-600 font-semibold">
                                {parsedResults.hostsUp || scan.devicesFound || 0}
                              </p>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Open Ports:</span>
                              <p className="text-blue-600 font-semibold">
                                {parsedResults.openPorts || scan.openPorts || 0}
                              </p>
                            </div>
                          </div>
                          
                          {/* Enhanced Results Display */}
                          <div className="bg-muted/30 rounded-lg p-4 mb-4">
                            <h4 className="font-medium text-card-foreground mb-2">Scan Results:</h4>
                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-sm">
                              <div>
                                <span className="text-muted-foreground">Hosts Up:</span>
                                <p className="text-green-600 font-medium">{parsedResults.hostsUp || 0}</p>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Hosts Down:</span>
                                <p className="text-gray-500">{parsedResults.hostsDown || 0}</p>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Open Ports:</span>
                                <p className="text-blue-600 font-medium">{parsedResults.openPorts || 0}</p>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Closed Ports:</span>
                                <p className="text-gray-500">{parsedResults.closedPorts || 0}</p>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Services:</span>
                                <p className="text-purple-600 font-medium">{parsedResults.services?.length || scan.services?.length || 0}</p>
                              </div>
                            </div>
                            
                            {/* Services Preview */}
                            {(parsedResults.services?.length > 0 || scan.services?.length > 0) && (
                              <div className="mt-3 pt-3 border-t border-border">
                                <h5 className="text-xs font-medium text-muted-foreground mb-2">Services Found:</h5>
                                <div className="flex flex-wrap gap-1">
                                  {(parsedResults.services || scan.services || []).slice(0, 6).map((service, idx) => (
                                    <Badge key={idx} variant="outline" className="text-xs">
                                      {service.port}: {service.service}
                                    </Badge>
                                  ))}
                                  {(parsedResults.services?.length || scan.services?.length || 0) > 6 && (
                                    <Badge variant="outline" className="text-xs">
                                      +{(parsedResults.services?.length || scan.services?.length || 0) - 6} more
                                    </Badge>
                                  )}
                                </div>
                              </div>
                            )}
                          </div>
                          
                          {/* Vulnerabilities */}
                          {(scan.vulnerabilities > 0 || parsedResults.vulnerabilities?.length > 0) && (
                            <div className="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-4">
                              <div className="flex items-center space-x-2">
                                <AlertTriangle className="w-4 h-4 text-red-500" />
                                <span className="font-medium text-red-800 dark:text-red-400">
                                  Vulnerabilities Found:
                                </span>
                                <span className="text-red-700 dark:text-red-300">
                                  {scan.vulnerabilities || parsedResults.vulnerabilities?.length || 0}
                                </span>
                              </div>
                              {parsedResults.vulnerabilities?.length > 0 && (
                                <div className="mt-2 text-sm text-red-700 dark:text-red-300">
                                  {parsedResults.vulnerabilities.slice(0, 3).map((vuln, idx) => (
                                    <div key={idx} className="truncate">• {vuln.description}</div>
                                  ))}
                                  {parsedResults.vulnerabilities.length > 3 && (
                                    <div className="text-xs">+{parsedResults.vulnerabilities.length - 3} more vulnerabilities</div>
                                  )}
                                </div>
                              )}
                            </div>
                          )}
                          
                          {/* Error Display */}
                          {scan.error && (
                            <div className="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-4">
                              <div className="flex items-center space-x-2">
                                <XCircle className="w-4 h-4 text-red-500" />
                                <span className="font-medium text-red-800 dark:text-red-400">Error:</span>
                              </div>
                              <p className="text-red-700 dark:text-red-300 text-sm mt-1">{scan.error}</p>
                            </div>
                          )}
                          
                          {/* Footer */}
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                              <span>Ports: {scan.ports || 'default'}</span>
                              {scan.useScripts && (
                                <div className="flex items-center space-x-1">
                                  <Shield className="w-3 h-3" />
                                  <span>Vulnerability scripts enabled</span>
                                </div>
                              )}
                            </div>
                            <div className="flex space-x-2">
                              <Button 
                                variant="outline" 
                                size="sm" 
                                className="btn-outline-click"
                                onClick={() => showScanDetails(scan)}
                              >
                                <Eye className="w-3 h-3 mr-1" />
                                View Details
                              </Button>
                              <Button 
                                variant="outline" 
                                size="sm" 
                                className="btn-outline-click"
                                onClick={() => exportScanDetails(scan)}
                              >
                                <Download className="w-3 h-3 mr-1" />
                                Export
                              </Button>
                              <Button 
                                variant="outline" 
                                size="sm" 
                                className="btn-outline-click text-red-600 hover:text-red-700"
                                onClick={() => deleteScan(scan.id)}
                              >
                                <Trash2 className="w-3 h-3 mr-1" />
                                Delete
                              </Button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>

      {/* Detailed Scan Dialog */}
      <Dialog open={showDetailsDialog} onOpenChange={setShowDetailsDialog}>
        <DialogContent className="max-w-4xl max-h-[90vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              {selectedScan && getScanTypeIcon(selectedScan.type)}
              <span>
                {selectedScan?.type
                  ? selectedScan.type.charAt(0).toUpperCase() + selectedScan.type.slice(1)
                  : 'Unknown'} Scan Details
              </span>
            </DialogTitle>
            <DialogDescription>Comprehensive information about the selected scan</DialogDescription>
          </DialogHeader>
          {selectedScan && (
            <ScrollArea className="max-h-[70vh] pr-4">
              <div className="space-y-6">
                {/* General Information */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="font-medium text-card-foreground mb-3">General Information</h4>
                    <div className="space-y-3 text-sm">
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Scan ID:</span>
                        <span className="text-card-foreground font-mono">{selectedScan.id}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Type:</span>
                        <Badge className={getScanTypeColor(selectedScan.type)}>
                          {selectedScan.type}
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Status:</span>
                        <Badge className={getStatusColor(selectedScan.status)}>
                          {getStatusIcon(selectedScan.status)}
                          <span className="ml-1">{selectedScan.status}</span>
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Target:</span>
                        <span className="text-card-foreground font-mono break-all">{selectedScan.target}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Ports:</span>
                        <span className="text-card-foreground">{selectedScan.ports || 'default'}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Vulnerability Scripts:</span>
                        <Badge variant={selectedScan.useScripts ? "default" : "outline"}>
                          {selectedScan.useScripts ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <h4 className="font-medium text-card-foreground mb-3">Timing & Performance</h4>
                    <div className="space-y-3 text-sm">
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Started:</span>
                        <span className="text-card-foreground">{formatDateTime(selectedScan.startTime)}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Ended:</span>
                        <span className="text-card-foreground">{formatDateTime(selectedScan.endTime)}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Duration:</span>
                        <span className="text-card-foreground font-mono">
                          {selectedScan.duration || calculateDuration(selectedScan.startTime, selectedScan.endTime)}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Results Summary */}
                <div>
                  <h4 className="font-medium text-card-foreground mb-3">Results Summary</h4>
                  {selectedScan.result ? (
                    <div className="space-y-4">
                      {(() => {
                        const parsed = selectedScan.hostsUp !== undefined ? selectedScan : parseScanResults(selectedScan.result);
                        return (
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <Card className="p-4">
                              <div className="text-center">
                                <div className="text-2xl font-bold text-green-600">{parsed.hostsUp || 0}</div>
                                <div className="text-sm text-muted-foreground">Hosts Up</div>
                              </div>
                            </Card>
                            <Card className="p-4">
                              <div className="text-center">
                                <div className="text-2xl font-bold text-blue-600">{parsed.openPorts || 0}</div>
                                <div className="text-sm text-muted-foreground">Open Ports</div>
                              </div>
                            </Card>
                            <Card className="p-4">
                              <div className="text-center">
                                <div className="text-2xl font-bold text-purple-600">{parsed.services?.length || 0}</div>
                                <div className="text-sm text-muted-foreground">Services</div>
                              </div>
                            </Card>
                            <Card className="p-4">
                              <div className="text-center">
                                <div className="text-2xl font-bold text-red-600">{parsed.vulnerabilities?.length || selectedScan.vulnerabilities || 0}</div>
                                <div className="text-sm text-muted-foreground">Vulnerabilities</div>
                              </div>
                            </Card>
                          </div>
                        );
                      })()}
                      
                      {/* Services Detected */}
                      {(() => {
                        const services = selectedScan.services || parseScanResults(selectedScan.result).services || [];
                        return services.length > 0 && (
                          <div>
                            <h5 className="font-medium text-card-foreground mb-3">Services Detected ({services.length})</h5>
                            <div className="border border-border rounded-lg overflow-hidden">
                              <div className="max-h-64 overflow-y-auto">
                                <table className="w-full text-sm">
                                  <thead className="bg-muted/50 sticky top-0">
                                    <tr>
                                      <th className="p-3 text-left">Host</th>
                                      <th className="p-3 text-left">Port</th>
                                      <th className="p-3 text-left">Service</th>
                                      <th className="p-3 text-left">State</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {services.map((service, index) => (
                                      <tr key={index} className="border-t border-border hover:bg-muted/30">
                                        <td className="p-3 font-mono text-xs">{service.host || 'N/A'}</td>
                                        <td className="p-3 font-mono">{service.port}</td>
                                        <td className="p-3">{service.service}</td>
                                        <td className="p-3">
                                          <Badge variant={service.state === 'open' ? 'default' : 'outline'} className="text-xs">
                                            {service.state || 'open'}
                                          </Badge>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                          </div>
                        );
                      })()}
                      
                      {/* Vulnerabilities */}
                      {(() => {
                        const vulns = selectedScan.vulnerabilityDetails || parseScanResults(selectedScan.result).vulnerabilities || [];
                        return vulns.length > 0 && (
                          <div>
                            <h5 className="font-medium text-card-foreground mb-3 flex items-center space-x-2">
                              <AlertTriangle className="w-4 h-4 text-red-500" />
                              <span>Vulnerabilities ({vulns.length})</span>
                            </h5>
                            <div className="border border-red-200 rounded-lg overflow-hidden bg-red-50/50 dark:bg-red-900/10">
                              <div className="max-h-64 overflow-y-auto">
                                <table className="w-full text-sm">
                                  <thead className="bg-red-100 dark:bg-red-900/20 sticky top-0">
                                    <tr>
                                      <th className="p-3 text-left">Host</th>
                                      <th className="p-3 text-left">Description</th>
                                      <th className="p-3 text-left">Severity</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {vulns.map((vuln, index) => (
                                      <tr key={index} className="border-t border-red-200 hover:bg-red-100/50">
                                        <td className="p-3 font-mono text-xs">{vuln.host || 'N/A'}</td>
                                        <td className="p-3 break-words">{vuln.description || 'No description'}</td>
                                        <td className="p-3">
                                          <Badge variant="outline" className="text-xs border-red-300">
                                            {vuln.severity || 'Unknown'}
                                          </Badge>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                          </div>
                        );
                      })()}
                    </div>
                  ) : (
                    <p className="text-muted-foreground">No scan results available</p>
                  )}
                </div>
                
                {/* Raw Output */}
                {(selectedScan.result || selectedScan.rawOutput) && (
                  <div>
                    <h4 className="font-medium text-card-foreground mb-3">Raw Scan Output</h4>
                    <div className="bg-muted/30 rounded-lg p-4 max-h-64 overflow-y-auto">
                      <pre className="text-xs font-mono whitespace-pre-wrap break-words">
                        {typeof (selectedScan.rawOutput || selectedScan.result) === 'string' 
                          ? (selectedScan.rawOutput || selectedScan.result) 
                          : JSON.stringify((selectedScan.rawOutput || selectedScan.result), null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
                
                {/* Error Information */}
                {selectedScan.error && (
                  <div className="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-4">
                    <div className="flex items-center space-x-2 mb-2">
                      <XCircle className="w-5 h-5 text-red-500" />
                      <span className="font-medium text-red-800 dark:text-red-400">Scan Error</span>
                    </div>
                    <p className="text-red-700 dark:text-red-300 text-sm">{selectedScan.error}</p>
                  </div>
                )}
                
                {/* Action Buttons */}
                <div className="flex justify-end space-x-3 pt-4 border-t border-border">
                  <Button 
                    variant="outline" 
                    onClick={() => exportScanDetails(selectedScan)}
                    className="btn-outline-click"
                  >
                    <Download className="w-4 h-4 mr-2" />
                    Export Scan Data
                  </Button>
                  <Button 
                    variant="outline" 
                    onClick={() => setShowDetailsDialog(false)}
                    className="btn-outline-click"
                  >
                    Close
                  </Button>
                </div>
              </div>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default ScanHistory;
