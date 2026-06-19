import { Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanDetail from './pages/ScanDetail'
import ContractDetail from './pages/ContractDetail'
import FindingDetail from './pages/FindingDetail'
import Settings from './pages/Settings'
import ToolHealth from './pages/ToolHealth'

export default function App() {
  return (
    <div className="flex h-full min-h-screen bg-slate-950">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl px-6 py-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scans/new" element={<NewScan />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/targets/:id" element={<ContractDetail />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="/health" element={<ToolHealth />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}
