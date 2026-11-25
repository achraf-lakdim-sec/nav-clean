import React, { useEffect, useState } from 'react'
import axios from 'axios'

const DetectInfo = () => {
  const [localIP, setLocalIP] = useState('')
  const [subnetInfo, setSubnetInfo] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    axios.get('http://127.0.0.1:8000/detect')
      .then((res) => {
        setLocalIP(res.data.local_ip)
        setSubnetInfo(res.data.subnet_info)
      })
      .catch((err) => {
        console.error(err)
        setError('Failed to fetch subnet info')
      })
  }, [])

  return (
    <div className="p-4 border rounded shadow-md bg-white dark:bg-gray-900">
      <h2 className="text-xl font-bold mb-4">🧠 Network Detection Info</h2>
      {error && <p className="text-red-500">{error}</p>}
      {localIP && <p><strong>Local IP:</strong> {localIP}</p>}
      {subnetInfo && (
        <div className="mt-2 space-y-1">
          <p><strong>Network Address:</strong> {subnetInfo.network_address}</p>
          <p><strong>Broadcast Address:</strong> {subnetInfo.broadcast_address}</p>
          <p><strong>Subnet Mask:</strong> {subnetInfo.subnet_mask}</p>
          <p><strong>CIDR:</strong> {subnetInfo.cidr}</p>
          <p><strong>Total Hosts:</strong> {subnetInfo.total_hosts}</p>
          <p><strong>First Host:</strong> {subnetInfo.first_host}</p>
          <p><strong>Last Host:</strong> {subnetInfo.last_host}</p>
        </div>
      )}
    </div>
  )
}

export default DetectInfo
