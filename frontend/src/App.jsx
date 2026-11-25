import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import './App.css'

// Components
import Sidebar from './components/Sidebar'
import Dashboard from './components/Dashboard'
import NetworkMap from './components/NetworkMap'

import DeviceList from './components/DeviceList'
import VulnerabilityList from './components/VulnerabilityList'
import ScanHistory from './components/ScanHistory'
import ScanConfiguration from './components/ScanConfiguration'

function App() {
  const [darkMode, setDarkMode] = useState(true)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)

  // Apply dark mode class to document
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [darkMode])

  const toggleDarkMode = () => {
    setDarkMode(!darkMode)
  }

  const toggleSidebar = () => {
    setSidebarCollapsed(!sidebarCollapsed)
  }

  return (
    <Router>
      <div className="flex h-screen bg-background text-foreground">
        <Sidebar 
          collapsed={sidebarCollapsed}
          onToggle={toggleSidebar}
          darkMode={darkMode}
          onToggleDarkMode={toggleDarkMode}
        />
        
        <main className={`flex-1 overflow-auto transition-all duration-300 ${
          sidebarCollapsed ? 'ml-16' : 'ml-64'
        }`}>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/network-map" element={<NetworkMap/>} />
            <Route path="/devices" element={<DeviceList />} />
            <Route path="/vulnerabilities" element={<VulnerabilityList />} />
            <Route path="/scan-history" element={<ScanHistory />} />
            <Route path="/scan-configuration" element={<ScanConfiguration />} />
          </Routes>
        </main>
      </div>
    </Router>
  )
}

export default App

