import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import {
  Monitor,
  Shield,
  Activity,
  Clock,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Wifi,
  Server,
  Smartphone,
  Laptop,
  Loader2,
  Zap,
  Router
} from 'lucide-react'
import axios from 'axios'

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalDevices: 0,
    vulnerabilities: 0,
    securityScore: 100,
    lastScan: 'Never',
    totalScans: 0,
    completedScans: 0,
    failedScans: 0,
    successRate: 0,
    scanTypeDistribution: {}
  })
  const [recentActivity, setRecentActivity] = useState([])
  const [deviceTypes, setDeviceTypes] = useState([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)

  const API_BASE = 'http://127.0.0.1:8000'

  const fetchDashboardData = async () => {
    setLoading(true)
    try {
      // Load scan history from localStorage first (same as ScanHistory)
      let scanHistory = []
      try {
        const savedHistory = localStorage.getItem('scanHistory')
        if (savedHistory) {
          scanHistory = JSON.parse(savedHistory)
          console.log('Dashboard: Loaded from localStorage:', scanHistory.length, 'scans')
        }
      } catch (parseError) {
        console.error('Dashboard: Error parsing localStorage data:', parseError)
        localStorage.removeItem('scanHistory')
      }

      // Calculate stats from scan history
      const totalScans = scanHistory.length
      const completedScans = scanHistory.filter(s => s.status === 'completed').length
      const failedScans = scanHistory.filter(s => s.status === 'failed').length
      const successRate = totalScans > 0 ? (completedScans / totalScans) * 100 : 0

      // Get latest completed scan for current stats
      const latestCompletedScan = scanHistory.find(scan => scan.status === 'completed')
      
      let currentDevices = 0
      let currentVulnerabilities = 0
      let lastScanTime = 'Never'
      
      if (latestCompletedScan) {
        // Use data from the latest scan, not sum of all scans
        currentDevices = latestCompletedScan.hostsUp || latestCompletedScan.devicesFound || 0
        currentVulnerabilities = latestCompletedScan.vulnerabilities || 0
        lastScanTime = latestCompletedScan.startTime || latestCompletedScan.timestamp
      }

      // Calculate security score based on latest scan only
      const securityScore = Math.max(0, 100 - (currentVulnerabilities * 5) - (failedScans * 2))

      setStats({
        totalDevices: currentDevices, // Latest scan devices, not total
        vulnerabilities: currentVulnerabilities, // Latest scan vulnerabilities, not total
        securityScore: securityScore,
        lastScan: lastScanTime === 'Never' ? 'Never' : formatLastSeen(lastScanTime),
        totalScans: totalScans,
        completedScans: completedScans,
        failedScans: failedScans,
        successRate: successRate,
        scanTypeDistribution: {}
      })

      // Process recent activity from scan history
      const activity = scanHistory.slice(0, 5).map(scan => ({
        id: scan.id,
        type: 'scan',
        message: `${scan.type.charAt(0).toUpperCase() + scan.type.slice(1)} scan completed on ${scan.target || 'network'}`,
        time: formatLastSeen(scan.startTime || scan.timestamp),
        status: scan.status === 'completed' ? 'success' : 'warning'
      }))
      setRecentActivity(activity)

      // Process device types from latest scan
      if (latestCompletedScan && latestCompletedScan.result) {
        const parsedResult = parseScanResults(latestCompletedScan.result)
        const deviceTypeCounts = parsedResult.allHosts.reduce((acc, host) => {
          const type = detectDeviceType(host.services || [], host.ports || [], host.hostname || '', host.ip || '')
          acc[type] = (acc[type] || 0) + 1
          return acc
        }, {})

        const typesArray = Object.entries(deviceTypeCounts).map(([type, count]) => {
          let Icon, color
          switch (type) {
            case 'laptop': Icon = Laptop; color = 'text-blue-500'; break;
            case 'server': Icon = Server; color = 'text-green-500'; break;
            case 'mobile': Icon = Smartphone; color = 'text-purple-500'; break;
            case 'iot': Icon = Wifi; color = 'text-orange-500'; break;
            case 'router': Icon = Router; color = 'text-red-500'; break;
            default: Icon = Monitor; color = 'text-gray-500';
          }
          return { type: type.charAt(0).toUpperCase() + type.slice(1) + 's', count, icon: Icon, color }
        })
        setDeviceTypes(typesArray)
      } else {
        setDeviceTypes([])
      }

    } catch (error) {
      console.error('Error fetching dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  const runQuickScan = async () => {
    setScanning(true)
    try {
      console.log('Starting quick scan from dashboard...')
      const response = await axios.get(`${API_BASE}/quick-scan`)
      console.log('Quick scan completed from dashboard:', response.data)

      const scanData = {
        id: Date.now(),
        type: 'quick',
        target: response.data.target || response.data.subnet || 'auto-detected',
        status: 'completed',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        ports: '22,80,443',
        useScripts: false,
        result: response.data.result,
        rawOutput: response.data.result,
        timestamp: new Date().toISOString()
      }

      const parsed = parseScanResults(response.data.result)
      scanData.hostsUp = parsed.hostsUp
      scanData.services = parsed.services
      scanData.vulnerabilities = parsed.vulnerabilities.length
      scanData.vulnerabilityDetails = parsed.vulnerabilities
      scanData.openPorts = parsed.services.length
      scanData.devicesFound = parsed.allHosts.length

      // Save to localStorage (same method as ScanHistory)
      const savedHistory = localStorage.getItem('scanHistory')
      let scanHistory = []
      try {
        if (savedHistory) {
          scanHistory = JSON.parse(savedHistory)
        }
      } catch (e) {
        console.error('Error parsing scan history:', e)
        scanHistory = []
      }
      
      const updatedHistory = [scanData, ...scanHistory].slice(0, 100)
      localStorage.setItem('scanHistory', JSON.stringify(updatedHistory))
      console.log('Quick scan saved to localStorage from dashboard')

      // Also try to save to backend
      try {
        await axios.post(`${API_BASE}/save-scan-history`, scanData)
        console.log('Quick scan saved to backend from dashboard')
      } catch (backendError) {
        console.warn('Could not save to backend:', backendError.message)
      }

      // Refresh dashboard data after scan
      setTimeout(() => {
        fetchDashboardData()
        setScanning(false)
      }, 500)

    } catch (error) {
      console.error('Quick scan failed from dashboard:', error)
      setScanning(false)
    }
  }

  useEffect(() => {
    fetchDashboardData()
  }, [])

  const formatLastSeen = (timestamp) => {
    try {
      const date = new Date(timestamp)
      const now = new Date()
      const diffMs = now - date
      const diffMins = Math.floor(diffMs / 60000)
      const diffHours = Math.floor(diffMs / 3600000)
      const diffDays = Math.floor(diffMs / 86400000)
      
      if (diffMins < 1) return 'Just now'
      if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`
      if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`
      return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`
    } catch {
      return 'Unknown'
    }
  }

  const getSecurityScoreColor = (score) => {
    if (score >= 90) return 'text-green-500'
    if (score >= 70) return 'text-yellow-500'
    return 'text-red-500'
  }

  const getActivityIcon = (type, status) => {
    if (type === 'scan') return <Activity className="w-4 h-4 text-blue-500" />
    if (type === 'vulnerability') return <AlertTriangle className="w-4 h-4 text-red-500" />
    if (type === 'device') return <Monitor className="w-4 h-4 text-green-500" />
    return <CheckCircle className="w-4 h-4 text-gray-500" />
  }

  // Helper functions for parsing scan results and detecting device types
  const parseScanResults = (result) => {
    if (!result) return { hostsUp: 0, services: [], vulnerabilities: [], allHosts: [] }

    if (typeof result === 'object' && !Array.isArray(result)) {
      return {
        hostsUp: result.hostsUp || result.hosts_up || 0,
        services: result.services || [],
        vulnerabilities: result.vulnerabilities || result.vulnerabilityDetails || [],
        allHosts: result.allHosts || []
      }
    }

    if (typeof result === 'string') {
      try {
        const lines = result.split('\n')
        let hostsUp = 0
        let services = []
        let vulnerabilities = []
        let allHosts = []
        let currentHost = null
        let currentHostObj = null

        for (const line of lines) {
          const trimmedLine = line.trim()
          
          if (trimmedLine.includes('Nmap scan report for')) {
            const hostMatch = trimmedLine.match(/Nmap scan report for (.+?)(\s|$)/)
            if (hostMatch) {
              currentHost = hostMatch[1].replace(/[()]/g, '').trim()
              
              currentHostObj = {
                ip: currentHost,
                hostname: currentHost,
                status: 'unknown',
                hasServices: false,
                serviceCount: 0,
                portCount: 0
              }
              
              allHosts.push(currentHostObj)
            }
          }
          
          if (trimmedLine.includes('Host is up') && currentHostObj) {
            currentHostObj.status = 'up'
            hostsUp++
          } else if (trimmedLine.includes('Host is down') && currentHostObj) {
            currentHostObj.status = 'down'
          }
          
          if (trimmedLine.match(/^\d+\/\w+\s+open/) && currentHost && currentHostObj) {
            const serviceMatch = trimmedLine.match(/^(\d+)\/(\w+)\s+open\s+(.+)/)
            if (serviceMatch) {
              services.push({
                host: currentHost,
                port: serviceMatch[1],
                protocol: serviceMatch[2],
                service: serviceMatch[3].trim(),
                state: 'open'
              })
              
              currentHostObj.hasServices = true
              currentHostObj.serviceCount++
              currentHostObj.portCount++
            }
          }
          
          if (trimmedLine.includes('VULNERABLE') || trimmedLine.includes('CVE-')) {
            vulnerabilities.push({
              host: currentHost || 'Unknown',
              description: trimmedLine,
              severity: trimmedLine.includes('CRITICAL') ? 'critical' : 
                       trimmedLine.includes('HIGH') ? 'high' :
                       trimmedLine.includes('MEDIUM') ? 'medium' : 'low'
            })
          }
          
          const summaryMatch = trimmedLine.match(/Nmap done: (\d+) IP addresses \((\d+) hosts up\)/)
          if (summaryMatch) {
            const summaryHostsUp = parseInt(summaryMatch[2])
            if (summaryHostsUp > hostsUp) {
              hostsUp = summaryHostsUp
            }
          }

          if (trimmedLine.match(/^\d+\.\d+\.\d+\.\d+$/)) {
            const ip = trimmedLine.trim()
            if (!allHosts.some(h => h.ip === ip)) {
              allHosts.push({
                ip: ip,
                hostname: ip,
                status: 'up',
                hasServices: false,
                serviceCount: 0,
                portCount: 0
              })
            }
          }
        }

        return { hostsUp, services, vulnerabilities, allHosts }
      } catch (error) {
        console.error('Error parsing scan results:', error)
        return { hostsUp: 0, services: [], vulnerabilities: [], allHosts: [] }
      }
    }

    return { hostsUp: 0, services: [], vulnerabilities: [], allHosts: [] }
  }

  const detectDeviceType = (services = [], ports = [], hostname = '', ip = '') => {
    const serviceList = services.map(s => s.service?.toLowerCase() || '').join(' ')
    const portList = ports.map(p => String(p)).join(',')
    const host = hostname.toLowerCase()

    if (ip.endsWith('.1') || host.includes('router') || host.includes('gateway') || host.includes('firewall') ||
        serviceList.includes('snmp') || portList.includes('161') || portList.includes('162') ||
        (serviceList.includes('http') && (portList.includes('80') || portList.includes('8080')) && 
         (serviceList.includes('ssh') || portList.includes('22')))) {
      return 'router'
    }

    if (serviceList.includes('apache') || serviceList.includes('nginx') || 
        serviceList.includes('mysql') || serviceList.includes('postgres') ||
        serviceList.includes('ftp') || serviceList.includes('ssh') ||
        portList.includes('3306') || portList.includes('5432') || 
        portList.includes('21') || portList.includes('22') ||
        (portList.includes('80') && portList.includes('443')) ||
        portList.includes('8080') || portList.includes('8443') ||
        services.length >= 3) {
      return 'server'
    }

    if (host.includes('camera') || host.includes('tv') || host.includes('smart') ||
        host.includes('iot') || host.includes('sensor') || host.includes('printer') ||
        serviceList.includes('rtsp') || serviceList.includes('upnp') ||
        portList.includes('554') || portList.includes('1900') ||
        portList.includes('8000') || portList.includes('9000') ||
        portList.includes('631')) {
      return 'iot'
    }

    if (host.includes('iphone') || host.includes('android') || host.includes('mobile') ||
        host.includes('phone') || host.includes('tablet') || host.includes('ipad')) {
      return 'mobile'
    }

    return services.length > 0 ? 'laptop' : 'unknown'
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Network Security Dashboard</h1>
          <p className="text-muted-foreground">Monitor your network security posture and scan activities</p>
        </div>
        <Button onClick={runQuickScan} disabled={scanning} className="btn-primary-click">
          {scanning ? (
            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
          ) : (
            <Zap className="w-4 h-4 mr-2" />
          )}
          {scanning ? 'Scanning...' : 'Start Quick Scan'}
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-card-foreground">Latest Scan Devices</CardTitle>
            <Monitor className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-card-foreground">{stats.totalDevices}</div>
            <p className="text-xs text-muted-foreground">
              {stats.totalDevices > 0 ? `${stats.totalDevices} discovered in latest scan` : 'No devices discovered yet'}
            </p>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-card-foreground">Latest Scan Vulnerabilities</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-card-foreground">{stats.vulnerabilities}</div>
            <p className="text-xs text-muted-foreground">
              {stats.vulnerabilities > 0 ? `${stats.vulnerabilities} detected in latest scan` : 'No vulnerabilities detected'}
            </p>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-card-foreground">Security Score</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${getSecurityScoreColor(stats.securityScore)}`}>
              {stats.securityScore}%
            </div>
            <p className="text-xs text-muted-foreground">Network security rating</p>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-card-foreground">Last Scan</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-card-foreground">
              {stats.lastScan === 'Never' ? 'Never' : stats.lastScan}
            </div>
            <p className="text-xs text-muted-foreground">
              {stats.lastScan === 'Never' ? 'No scans performed' : `Updated ${stats.lastScan}`}
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Device Types */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-card-foreground">Device Types (Latest Scan)</CardTitle>
            <CardDescription>Distribution of discovered devices from most recent scan</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {deviceTypes.length > 0 ? (
              deviceTypes.map((device, index) => {
                const Icon = device.icon
                return (
                  <div key={index} className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <Icon className={`w-5 h-5 ${device.color}`} />
                      <span className="text-card-foreground">{device.type}</span>
                    </div>
                    <Badge variant="secondary" className="bg-secondary text-secondary-foreground">
                      {device.count}
                    </Badge>
                  </div>
                )
              })
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Monitor className="w-12 h-12 mx-auto mb-4 text-muted-foreground/50" />
                <p>No devices discovered yet</p>
                <p className="text-sm">Run a scan to discover network devices</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-card-foreground">Recent Scan Activity</CardTitle>
            <CardDescription>Latest network scanning results</CardDescription>
          </CardHeader>
          <CardContent>
            {recentActivity.length > 0 ? (
              <div className="space-y-4">
                {recentActivity.map((activity) => (
                  <div key={activity.id} className="flex items-start space-x-3 p-3 rounded-lg bg-muted/50">
                    {getActivityIcon(activity.type, activity.status)}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-card-foreground">{activity.message}</p>
                      <p className="text-xs text-muted-foreground">{activity.time}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Activity className="w-12 h-12 mx-auto mb-4 text-muted-foreground/50" />
                <p>No scan history available</p>
                <p className="text-sm">Start your first scan to see activity</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Security Score Progress */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-card-foreground">Scan Statistics</CardTitle>
          <CardDescription>Overview of scan performance and outcomes</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-card-foreground">Total Scans</span>
              <span className="text-sm font-medium text-card-foreground">{stats.totalScans}</span>
            </div>
            <Progress value={(stats.totalScans / (stats.totalScans || 1)) * 100} className="h-2" />
          </div>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-card-foreground">Completed Scans</span>
              <span className="text-sm font-medium text-card-foreground">{stats.completedScans}</span>
            </div>
            <Progress value={(stats.completedScans / (stats.totalScans || 1)) * 100} className="h-2" />
          </div>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-card-foreground">Failed Scans</span>
              <span className="text-sm font-medium text-card-foreground">{stats.failedScans}</span>
            </div>
            <Progress value={(stats.failedScans / (stats.totalScans || 1)) * 100} className="h-2" />
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-card-foreground">Success Rate</span>
              <span className="text-sm font-medium text-card-foreground">{stats.successRate.toFixed(2)}%</span>
            </div>
            <Progress value={stats.successRate} className="h-2" />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

export default Dashboard
