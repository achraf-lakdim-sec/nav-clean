import { useState, useEffect, useRef, useCallback } from 'react';
import { Network as VisNetwork } from 'vis-network';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { 
  Loader2, Network as NetworkIcon, Server, Router as RouterIcon, 
  Laptop, Smartphone, HelpCircle, Expand, Target
} from 'lucide-react';

// --- Configuration for a more beautiful look ---

const DEVICE_ICONS = {
  router: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="10" width="18" height="12" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/><path d="M12 16v-2"/><path d="M8.5 22v-2"/><path d="M15.5 22v-2"/></svg>`,
  server: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`,
  laptop: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55A1 1 0 0 1 20.28 20H3.72a1 1 0 0 1-.98-1.45L4 16Z"/></svg>`,
  iot: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22a2.9 2.9 0 0 0 3-3 2.9 2.9 0 0 0-3-3 2.9 2.9 0 0 0-3 3 2.9 2.9 0 0 0 3 3Z"/><path d="M19 19a9 9 0 1 0-14 0"/><path d="M15.91 14.09a5 5 0 0 0-7.82 0"/></svg>`,
  unknown: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>`,
};

const STATUS_COLORS = {
  online: '#22c55e', // green-500
  offline: '#6b7280', // gray-500
  high_risk: '#ef4444', // red-500
};


const NetworkMap = () => {
    const [devices, setDevices] = useState([]);
    const [loading, setLoading] = useState(true);
    const networkContainer = useRef(null);
    const networkInstance = useRef(null);

    // --- ENHANCED PARSING LOGIC ---
    // This improved parser tries to determine a status and risk for better visuals.
    const extractDevicesFromHistory = useCallback((scanHistory) => {
        if (!scanHistory || scanHistory.length === 0) return [];
        const latestScan = scanHistory.find(s => s.status === 'completed' && (s.result || s.rawOutput));
        if (!latestScan) return [];
        
        const hostMap = new Map();
        let currentHostInfo = null;

        (latestScan.rawOutput || latestScan.result).split('\n').forEach(line => {
            if (line.includes('Nmap scan report for')) {
                const hostMatch = line.match(/for (.*?)(?: \((.*?)\))?$/);
                const ip = hostMatch[2] || hostMatch[1];
                if (ip && !hostMap.has(ip)) {
                    currentHostInfo = {
                        id: ip,
                        ip: ip,
                        hostname: hostMatch[1] === ip ? `Host (${ip})` : hostMatch[1],
                        type: 'unknown',
                        status: 'offline', // Assume offline until a port is found
                        risk: 'low',
                        openPorts: 0,
                    };
                    hostMap.set(ip, currentHostInfo);
                }
            } else if (currentHostInfo && line.match(/^\d+\/tcp\s+open/)) {
                currentHostInfo.status = 'online';
                currentHostInfo.openPorts += 1;
            } else if (currentHostInfo && line.includes('VULNERABLE')) {
                 currentHostInfo.risk = 'high';
            }
        });
        
        // Final pass to determine type
        hostMap.forEach(host => {
          if (host.hostname.toLowerCase().includes('router') || host.hostname.toLowerCase().includes('gateway')) host.type = 'router';
          else if (host.openPorts > 5) host.type = 'server';
          else if (host.status === 'online') host.type = 'laptop';
          else host.type = 'iot';
        });

        return Array.from(hostMap.values());
    }, []);

    const fetchData = useCallback(() => {
        setLoading(true);
        try {
            const savedHistory = localStorage.getItem('scanHistory');
            const history = savedHistory ? JSON.parse(savedHistory) : [];
            const extractedDevices = extractDevicesFromHistory(history);
            setDevices(extractedDevices);
        } catch (error) {
            console.error("NetworkMap failed to parse history:", error);
            setDevices([]);
        } finally {
            setLoading(false);
        }
    }, [extractDevicesFromHistory]);
    
    // This effect handles the event listening.
    useEffect(() => {
        fetchData();
        window.addEventListener('scanHistoryUpdated', fetchData);
        return () => window.removeEventListener('scanHistoryUpdated', fetchData);
    }, [fetchData]);

    // --- VISUALIZATION LOGIC ---
    // This effect handles drawing and updating the network graph.
    useEffect(() => {
        if (!networkContainer.current) return;
        
        if (devices.length === 0) {
             if (networkInstance.current) networkInstance.current.destroy();
             return;
        }

        const getDeviceNode = (device) => {
            const color = device.risk === 'high' ? STATUS_COLORS.high_risk : STATUS_COLORS[device.status];
            const iconSVG = DEVICE_ICONS[device.type] || DEVICE_ICONS.unknown;
            const coloredSVG = iconSVG.replace('currentColor', color);
            
            // Rich HTML tooltip on hover
            const tooltip = document.createElement('div');
            tooltip.className = 'p-2 bg-gray-800 text-white rounded-lg shadow-lg border border-gray-700';
            tooltip.innerHTML = `
                <div class="font-bold text-base mb-1">${device.hostname}</div>
                <div class="font-mono text-sm text-cyan-400">${device.ip}</div>
                <hr class="my-1 border-gray-600">
                <div class="text-xs"><strong>Status:</strong> <span style="color:${color};">${device.status}</span></div>
                <div class="text-xs"><strong>Type:</strong> ${device.type}</div>
                <div class="text-xs"><strong>Open Ports:</strong> ${device.openPorts}</div>
                <div class="text-xs"><strong>Risk:</strong> <span style="color:${device.risk === 'high' ? STATUS_COLORS.high_risk : '#fff'};">${device.risk}</span></div>
            `;

            return {
                id: device.id,
                shape: 'image',
                image: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(coloredSVG)}`,
                size: 25,
                label: device.hostname,
                font: { color: '#e5e7eb', strokeWidth: 0 },
                color: {
                  border: color,
                  background: '#1f2937', // gray-800
                  highlight: {
                    border: color,
                    background: '#374151' // gray-700
                  }
                },
                borderWidth: 2,
                // Add a glow for online, non-risky devices
                shadow: (device.status === 'online' && device.risk !== 'high') ? {
                    enabled: true,
                    color: color,
                    size: 15,
                    x: 0, y: 0
                } : { enabled: false },
                title: tooltip,
            };
        };

        const nodes = devices.map(getDeviceNode);

        // Simple logic to connect all devices to the first discovered router, or just link them up
        const router = devices.find(d => d.type === 'router');
        const edges = router 
            ? devices.filter(d => d.id !== router.id).map(d => ({ from: router.id, to: d.id, arrows: 'to', color: '#4b5563' }))
            : (devices.length > 1 ? devices.slice(1).map((d, i) => ({ from: devices[i].id, to: d.id, arrows: 'to', color: '#4b5563' })) : []);

        const data = { nodes, edges };

        const options = {
            height: '500px',
            width: '100%',
            layout: {
                hierarchical: false
            },
            physics: {
                enabled: true,
                barnesHut: {
                    gravitationalConstant: -3000,
                    centralGravity: 0.1,
                    springLength: 150,
                    avoidOverlap: 0.5,
                },
                solver: 'barnesHut',
                stabilization: { iterations: 1000 },
            },
            interaction: {
                hover: true,
                tooltipDelay: 200,
            },
            nodes: {
              shapeProperties: {
                useImageSize: false,
              }
            },
            edges: {
              smooth: true
            }
        };

        if (networkInstance.current) networkInstance.current.destroy();
        networkInstance.current = new VisNetwork(networkContainer.current, data, options);
        networkInstance.current.fit(); // Automatically zoom to fit

    }, [devices]);

    // Helper component for the Legend
    const LegendItem = ({ icon, label }) => (
        <div className="flex items-center space-x-2">
            <div className="w-6 h-6 flex items-center justify-center" dangerouslySetInnerHTML={{ __html: icon.replace('currentColor', '#e5e7eb') }} />
            <span className="text-xs text-muted-foreground">{label}</span>
        </div>
    );

    return (
        <Card className="col-span-1 lg:col-span-3">
            <CardHeader>
                <div className="flex justify-between items-start">
                    <div>
                        <CardTitle className="text-xl">Live Network Topology</CardTitle>
                        <CardDescription>A creative and interactive visualization of the last network scan.</CardDescription>
                    </div>
                    <Button variant="outline" size="sm" onClick={() => networkInstance.current?.fit()}>
                        <Expand className="w-4 h-4 mr-2" />
                        Fit View
                    </Button>
                </div>
            </CardHeader>
            <CardContent className="relative bg-gray-900/50 rounded-lg p-0" style={{ backgroundImage: 'radial-gradient(circle, rgba(255,255,255,0.05) 1px, transparent 1px)', backgroundSize: '20px 20px' }}>
                {loading ? (
                    <div className="flex flex-col items-center justify-center h-[500px]">
                        <Loader2 className="w-10 h-10 animate-spin text-primary mb-4" />
                        <p className="text-lg">Analyzing Scan Data...</p>
                    </div>
                ) : devices.length > 0 ? (
                    <div ref={networkContainer} style={{ height: '500px' }} />
                ) : (
                    <div className="flex flex-col items-center justify-center h-[500px] text-muted-foreground">
                        <Target className="w-20 h-20 text-gray-700 mb-6" />
                        <h3 className="text-xl font-semibold text-foreground mb-2">Awaiting Scan Data</h3>
                        <p>The network map is ready.</p>
                        <p className="text-sm">Complete a new scan to visualize the results here.</p>
                    </div>
                )}
            </CardContent>
            <CardFooter className="pt-4 grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                 <h4 className="col-span-full text-sm font-semibold text-foreground">Legend</h4>
                 <LegendItem icon={DEVICE_ICONS.router} label="Router/Gateway" />
                 <LegendItem icon={DEVICE_ICONS.server} label="Server" />
                 <LegendItem icon={DEVICE_ICONS.laptop} label="Laptop/Desktop" />
                 <LegendItem icon={DEVICE_ICONS.iot} label="IoT/Misc Device" />
                 <LegendItem icon={DEVICE_ICONS.unknown} label="Unknown" />
                 <div className="flex items-center space-x-2">
                    <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
                    <span className="text-xs text-muted-foreground">Online Device</span>
                 </div>
            </CardFooter>
        </Card>
    );
};

export default NetworkMap;
