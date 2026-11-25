import { useState, useEffect, useCallback } from 'react';
import ReactFlow, {
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  addEdge,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import {
  Monitor,
  Server,
  Smartphone,
  Wifi,
  Router,
  Search,
  Filter,
  Eye,
  RefreshCw,
  Loader2,
  Unlock,
  Target,
  Network,
  List,
  GitFork,
  AlertTriangle
} from 'lucide-react';

const DeviceList = () => {
  const [devices, setDevices] = useState([]);
  const [filteredDevices, setFilteredDevices] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [showDetailsDialog, setShowDetailsDialog] = useState(false);
  const [lastScanInfo, setLastScanInfo] = useState(null);
  const [viewMode, setViewMode] = useState('list');

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  /**
   * --- CORRECTED DATA FETCHING LOGIC ---
   * This function now reads from the same 'scanHistory' localStorage item
   * that your ScanHistory.jsx component uses. This ensures both components
   * share the same source of truth.
   */
  const fetchDevices = useCallback(() => {
    setRefreshing(true);
    setLoading(true);
    console.log("DeviceList: Fetching data from localStorage...");

    try {
      const savedHistory = localStorage.getItem('scanHistory');
      if (savedHistory) {
        const history = JSON.parse(savedHistory);
        console.log(`DeviceList: Found ${history.length} scans in localStorage.`);
        
        // The extractDevicesFromLatestScan function will process the most recent scan
        const extractedDevices = extractDevicesFromLatestScan(history);
        setDevices(extractedDevices);
      } else {
        console.log("DeviceList: No scan history found in localStorage.");
        setDevices([]);
      }
    } catch (error) {
      console.error('DeviceList: Error parsing localStorage data:', error);
      setDevices([]); // Clear data on error
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []); // The function is wrapped in useCallback to stabilize its identity

  
  // The rest of the functions are the same as before, as they correctly process the data
  // once it's been fetched.

  const extractDevicesFromLatestScan = (scanHistory) => {
    if (!scanHistory || scanHistory.length === 0) {
        setLastScanInfo(null);
        return [];
    }

    const completedScans = scanHistory
        .filter(scan => scan.status === 'completed')
        .sort((a, b) => new Date(b.startTime || b.timestamp) - new Date(a.startTime || a.timestamp));

    if (completedScans.length === 0) {
        setLastScanInfo(null);
        return [];
    }
    
    const latestScan = completedScans[0];
    
    setLastScanInfo({
      type: latestScan.type,
      target: latestScan.target,
      timestamp: latestScan.startTime || latestScan.timestamp,
    });

    const parsed = parseScanResults(latestScan.rawOutput || latestScan.result);
    const hostMap = new Map();
    
    parsed.allHosts.forEach(host => {
      if (!host.ip) return;
      hostMap.set(host.ip, {
        id: host.ip.replace(/[^a-zA-Z0-9]/g, '_'),
        ip: host.ip,
        hostname: host.hostname || host.ip,
        services: [],
        ports: [],
        vulnerabilities: 0,
        vulnerabilityDetails: [],
        lastSeen: latestScan.startTime || latestScan.timestamp || new Date().toISOString(),
        status: host.status || 'up',
        mac: host.mac || 'N/A',
        vendor: host.vendor || 'Unknown',
        hasServices: false,
      });
    });

    parsed.services.forEach(service => {
      if (hostMap.has(service.host)) {
        const device = hostMap.get(service.host);
        device.services.push(service);
        if (!device.ports.includes(service.port)) {
          device.ports.push(service.port);
        }
        device.hasServices = true;
      }
    });
    
    parsed.vulnerabilities.forEach(vuln => {
        if(hostMap.has(vuln.host)) {
            const device = hostMap.get(vuln.host);
            device.vulnerabilities++;
            device.vulnerabilityDetails.push({ ...vuln, scanDate: latestScan.startTime });
        }
    });

    const devices = Array.from(hostMap.values()).map(device => {
      const type = detectDeviceType(device.services, device.ports, device.hostname, device.vendor);
      const risk = assessRisk(device.vulnerabilities, device.services, device.ports);
      let status = device.status;
      if (status === 'up' && device.hasServices) status = 'online';
      else if (status === 'up') status = 'detected';
      
      return { ...device, type, risk, status, lastSeen: formatLastSeen(device.lastSeen) };
    });

    return devices.sort((a, b) => {
        const aIp = a.ip.split('.').map(Number);
        const bIp = b.ip.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            if (aIp[i] !== bIp[i]) return aIp[i] - bIp[i];
        }
        return 0;
    });
  };

  const parseScanResults = (result) => {
    if (!result) return { allHosts: [], services: [], vulnerabilities: [] };
    if (typeof result !== 'string') return { allHosts: [], services: [], vulnerabilities: [] };
    
    const lines = result.split('\n');
    const allHosts = [];
    const services = [];
    const vulnerabilities = [];
    let currentHostInfo = null;

    for (const line of lines) {
        const trimmedLine = line.trim();
        if (trimmedLine.startsWith('Nmap scan report for')) {
            if (currentHostInfo) allHosts.push(currentHostInfo);
            const hostMatch = trimmedLine.match(/for\s(.+?)(?:\s\((.+?)\))?$/);
            currentHostInfo = {
                hostname: hostMatch[1],
                ip: hostMatch[2] || hostMatch[1],
                status: 'down',
                mac: null,
                vendor: null
            };
        } else if (currentHostInfo) {
            if (trimmedLine.startsWith('Host is up')) currentHostInfo.status = 'up';
            if (trimmedLine.startsWith('MAC Address:')) {
                const macMatch = trimmedLine.match(/MAC Address: ([0-9A-F:]+)\s\((.+)\)/);
                if (macMatch) {
                    currentHostInfo.mac = macMatch[1];
                    currentHostInfo.vendor = macMatch[2];
                }
            }
            if (trimmedLine.match(/^\d+\/\w+\s+open/)) {
                const serviceMatch = trimmedLine.match(/^(\d+\/\w+)\s+open\s+(.+)/);
                if (serviceMatch) {
                    services.push({
                        host: currentHostInfo.ip,
                        port: serviceMatch[1],
                        service: serviceMatch[2].trim(),
                    });
                }
            }
            if (trimmedLine.includes('VULNERABLE')) {
                vulnerabilities.push({
                    host: currentHostInfo.ip,
                    description: trimmedLine,
                    severity: 'high' 
                });
            }
        }
    }
    if (currentHostInfo) allHosts.push(currentHostInfo);
    return { allHosts: allHosts.filter(h => h.status === 'up'), services, vulnerabilities };
  };

  const detectDeviceType = (services = [], ports = [], hostname = '', vendor = '') => {
    const serviceString = services.map(s => s.service).join(' ').toLowerCase();
    const vendorLower = vendor.toLowerCase();
    if (vendorLower.includes('netgear') || vendorLower.includes('cisco') || serviceString.includes('http') && serviceString.includes('ssh')) return 'router';
    if (serviceString.includes('samba') || serviceString.includes('microsoft-ds') || serviceString.includes('mysql')) return 'server';
    if (vendorLower.includes('apple') || vendorLower.includes('samsung')) return 'mobile';
    if (serviceString.includes('ipp') || serviceString.includes('printer')) return 'iot';
    return 'laptop';
  };

  const assessRisk = (vulnerabilityCount, services = []) => {
    let riskScore = vulnerabilityCount * 2;
    const riskyServices = ['telnet', 'ftp'];
    if (services.some(s => riskyServices.includes(s.service))) riskScore += 3;
    if (riskScore > 5) return 'critical';
    if (riskScore > 3) return 'high';
    if (riskScore > 1) return 'medium';
    return 'low';
  };
  
  const formatLastSeen = (timestamp) => {
    const diff = (new Date() - new Date(timestamp)) / 60000; // a in minutes
    if (diff < 60) return `${Math.round(diff)}m ago`;
    if (diff < 1440) return `${Math.round(diff / 60)}h ago`;
    return `${Math.round(diff / 1440)}d ago`;
  };

  useEffect(() => {
    fetchDevices();

    // This listener will automatically refresh the device list if the localStorage
    // is updated by another tab (like the Scan History page).
    const handleStorageChange = (event) => {
        if (event.key === 'scanHistory') {
            console.log("DeviceList: Detected storage change. Refreshing data...");
            fetchDevices();
        }
    };

    window.addEventListener('storage', handleStorageChange);

    return () => {
        window.removeEventListener('storage', handleStorageChange);
    };
  }, [fetchDevices]);

  useEffect(() => {
    const filtered = devices.filter(device => {
        const searchTermLower = searchTerm.toLowerCase();
        return (
            (device.hostname.toLowerCase().includes(searchTermLower) ||
             device.ip.includes(searchTermLower) ||
             device.vendor.toLowerCase().includes(searchTermLower)) &&
            (statusFilter === 'all' || device.status === statusFilter) &&
            (typeFilter === 'all' || device.type === typeFilter) &&
            (riskFilter === 'all' || device.risk === riskFilter)
        );
    });
    setFilteredDevices(filtered);
  }, [devices, searchTerm, statusFilter, typeFilter, riskFilter]);

  useEffect(() => {
    const getRiskColor = (risk) => ({
      critical: '#EF4444', high: '#F59E0B', medium: '#EAB308', low: '#22C55E', default: '#6B7280'
    })[risk] || '#6B7280';

    const router = filteredDevices.find(d => d.type === 'router');
    const newNodes = filteredDevices.map((device, i) => ({
        id: device.id,
        position: { x: (i % 5) * 220, y: Math.floor(i / 5) * 160 },
        data: { label: `${device.hostname} (${device.ip})` },
        style: { background: getRiskColor(device.risk), color: 'white', width: 180, textAlign: 'center' }
    }));
    const newEdges = router ? filteredDevices.filter(d => d.id !== router.id).map(d => ({
        id: `e-${router.id}-${d.id}`, source: router.id, target: d.id, animated: true
    })) : [];

    setNodes(newNodes);
    setEdges(newEdges);
  }, [filteredDevices, setNodes, setEdges]);
  
  // Helper functions for UI (unchanged)
  const getDeviceIcon = (type) => {
    const IconMap = { router: Router, server: Server, mobile: Smartphone, iot: Wifi, laptop: Monitor };
    const Icon = IconMap[type] || Monitor;
    return <Icon className="w-8 h-8 text-muted-foreground" />;
  };
  const getRiskBadgeColor = (risk) => {
    const colorMap = { critical: 'bg-red-600', high: 'bg-red-500', medium: 'bg-yellow-500', low: 'bg-green-500' };
    return `${colorMap[risk] || 'bg-gray-500'} text-white`;
  };
  const getStatusBadgeColor = (status) => {
    const colorMap = { online: 'bg-green-100 text-green-800', detected: 'bg-blue-100 text-blue-800', offline: 'bg-gray-100 text-gray-800' };
    return colorMap[status];
  };

  const onConnect = useCallback((params) => setEdges((eds) => addEdge(params, eds)), [setEdges]);
  const openDeviceDetails = (device) => { setSelectedDevice(device); setShowDetailsDialog(true); };
  const deviceTypes = [...new Set(devices.map(d => d.type))];

  return (
    <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex justify-between items-center">
            <div>
                <h1 className="text-3xl font-bold">Device Dashboard</h1>
                <p className="text-muted-foreground">Live view of network devices from the latest scan.</p>
            </div>
            <div className="flex items-center space-x-2">
                <Button onClick={() => setViewMode(viewMode === 'list' ? 'graph' : 'list')} variant="outline">
                    {viewMode === 'list' ? <GitFork className="w-4 h-4 mr-2" /> : <List className="w-4 h-4 mr-2" />}
                    {viewMode === 'list' ? 'Graph View' : 'List View'}
                </Button>
                <Button onClick={fetchDevices} disabled={refreshing} variant="outline">
                    <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
                    Refresh
                </Button>
            </div>
        </div>

        {/* Filters */}
        <Card>
            <CardHeader><CardTitle>Filters</CardTitle></CardHeader>
            <CardContent className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Input placeholder="Search..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} />
                <Select value={statusFilter} onValueChange={setStatusFilter}><SelectTrigger><SelectValue/></SelectTrigger><SelectContent><SelectItem value="all">All Statuses</SelectItem><SelectItem value="online">Online</SelectItem><SelectItem value="detected">Detected</SelectItem></SelectContent></Select>
                <Select value={typeFilter} onValueChange={setTypeFilter}><SelectTrigger><SelectValue/></SelectTrigger><SelectContent><SelectItem value="all">All Types</SelectItem>{deviceTypes.map(t=><SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent></Select>
                <Select value={riskFilter} onValueChange={setRiskFilter}><SelectTrigger><SelectValue/></SelectTrigger><SelectContent><SelectItem value="all">All Risks</SelectItem><SelectItem value="critical">Critical</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="low">Low</SelectItem></SelectContent></Select>
            </CardContent>
        </Card>

        {/* Content */}
        {loading ? <div className="text-center py-20"><Loader2 className="w-12 h-12 animate-spin mx-auto" /></div> :
         (viewMode === 'list' ? (
            <Card>
                <CardHeader><CardTitle>Device List ({filteredDevices.length})</CardTitle><CardDescription>{lastScanInfo ? `Data from scan on ${lastScanInfo.target} at ${new Date(lastScanInfo.timestamp).toLocaleTimeString()}` : 'No scan data found.'}</CardDescription></CardHeader>
                <CardContent className="space-y-2">
                    {filteredDevices.length > 0 ? filteredDevices.map(device => (
                        <div key={device.id} onClick={() => openDeviceDetails(device)} className="flex items-center justify-between p-3 border rounded-md hover:bg-muted/50 cursor-pointer">
                            <div className="flex items-center space-x-4"><div className="p-2 bg-muted rounded-full">{getDeviceIcon(device.type)}</div><div><p className="font-semibold">{device.hostname}</p><p className="text-sm text-muted-foreground">{device.ip}</p></div></div>
                            <div className="flex items-center space-x-3"><Badge className={getStatusBadgeColor(device.status)}>{device.status}</Badge><Badge className={getRiskBadgeColor(device.risk)}>{device.risk} risk</Badge></div>
                        </div>
                    )) : <div className="text-center py-10 text-muted-foreground"><Network className="w-10 h-10 mx-auto mb-2"/>No devices match your criteria.</div>}
                </CardContent>
            </Card>
         ) : (
            <Card className="h-[700px]">
                <CardHeader><CardTitle>Network Graph</CardTitle></CardHeader>
                <CardContent className="h-full"><ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect} fitView><Controls /><MiniMap /><Background /></ReactFlow></CardContent>
            </Card>
         ))}

        {/* Dialog */}
        <Dialog open={showDetailsDialog} onOpenChange={setShowDetailsDialog}>
            <DialogContent className="max-w-3xl"><DialogHeader><DialogTitle>{selectedDevice?.hostname}</DialogTitle><DialogDescription>{selectedDevice?.ip}</DialogDescription></DialogHeader>
                {selectedDevice && <div className="grid grid-cols-2 gap-4 py-4">
                    <div><h4 className="font-bold">Info</h4><p>MAC: {selectedDevice.mac}</p><p>Vendor: {selectedDevice.vendor}</p><p>Risk: {selectedDevice.risk}</p></div>
                    <div><h4 className="font-bold">Services ({selectedDevice.services.length})</h4><ScrollArea className="h-40"><ul className="list-disc pl-5">{selectedDevice.services.map((s, i) => <li key={i}>{s.port}: {s.service}</li>)}</ul></ScrollArea></div>
                    {selectedDevice.vulnerabilities > 0 && <div className="col-span-2"><h4 className="font-bold text-red-500">Vulnerabilities</h4><ScrollArea className="h-24"><ul className="list-disc pl-5">{selectedDevice.vulnerabilityDetails.map((v,i)=><li key={i}>{v.description}</li>)}</ul></ScrollArea></div>}
                </div>}
            </DialogContent>
        </Dialog>
    </div>
  );
};

export default DeviceList;
