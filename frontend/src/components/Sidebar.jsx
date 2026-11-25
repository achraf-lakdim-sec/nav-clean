import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { 
  LayoutDashboard, 
  Network, 
  Monitor, 
  Shield, 
  History, 
  Settings,
  Menu,
  Sun,
  Moon,
  Zap
} from 'lucide-react'

const Sidebar = ({ collapsed, onToggle, darkMode, onToggleDarkMode }) => {
  const location = useLocation()
  
  const menuItems = [
    { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard', color: 'text-blue-500' },
    { path: '/network-map', icon: Network, label: 'Network Map', color: 'text-green-500' },
    { path: '/devices', icon: Monitor, label: 'Devices', color: 'text-yellow-500' },
    { path: '/vulnerabilities', icon: Shield, label: 'Vulnerabilities', color: 'text-red-500' },
    { path: '/scan-history', icon: History, label: 'Scan History', color: 'text-purple-500' },
    { path: '/scan-configuration', icon: Settings, label: 'Scan Configuration', color: 'text-pink-500' },
  ]

  return (
    <div className={`fixed left-0 top-0 h-full bg-sidebar border-r border-sidebar-border transition-all duration-300 z-50 ${
      collapsed ? 'w-16' : 'w-64'
    }`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-sidebar-border">
        {!collapsed && (
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
              <Zap className="w-5 h-5 text-primary-foreground" />
            </div>
            <div>
              <h1 className="font-bold text-sidebar-foreground">NAV</h1>
              <p className="text-xs text-sidebar-foreground/70">Network Analysis &amp; Visualization</p>
            </div>
          </div>
        )}
        
        <Button
          variant="ghost"
          size="sm"
          onClick={onToggle}
          className="btn-ghost-click p-2 hover:bg-sidebar-accent"
        >
          <Menu className="w-4 h-4" />
        </Button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-2">
        <ul className="space-y-1">
          {menuItems.map((item) => {
            const isActive = location.pathname === item.path
            const Icon = item.icon
            
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 group btn-ghost-click ${
                    isActive 
                      ? 'bg-sidebar-primary text-sidebar-primary-foreground shadow-sm' 
                      : 'text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground'
                  }`}
                >
                  <Icon className={`w-5 h-5 ${isActive ? 'text-sidebar-primary-foreground' : item.color}`} />
                  {!collapsed && (
                    <span className="font-medium truncate">{item.label}</span>
                  )}
                  {isActive && !collapsed && (
                    <div className="ml-auto w-2 h-2 bg-sidebar-primary-foreground rounded-full" />
                  )}
                </Link>
              </li>
            )
          })}
        </ul>
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-sidebar-border">
        <Button
          variant="ghost"
          size="sm"
          onClick={onToggleDarkMode}
          className={`btn-ghost-click w-full justify-start ${collapsed ? 'px-2' : 'px-3'}`}
        >
          {darkMode ? (
            <Sun className="w-4 h-4 text-yellow-500" />
          ) : (
            <Moon className="w-4 h-4 text-blue-500" />
          )}
          {!collapsed && (
            <span className="ml-3">
              {darkMode ? 'Light Mode' : 'Dark Mode'}
            </span>
          )}
        </Button>
        
      </div>
    </div>
  )
}

export default Sidebar

