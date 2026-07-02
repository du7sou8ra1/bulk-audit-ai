import { NavLink } from 'react-router-dom'
import ThemePicker from './ThemePicker'

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/scans', label: 'All Scans', end: true },
  { to: '/scans/new', label: 'New Scan', end: false },
  { to: '/monitor', label: 'Monitor', end: false },
  { to: '/health', label: 'Tool Health', end: false },
  { to: '/settings', label: 'Settings', end: false },
]

export default function Sidebar() {
  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-slate-800 bg-slate-900/60">
      <div className="px-5 py-5 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="h-7 w-7 rounded bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 font-mono text-sm font-bold">
            B
          </div>
          <span className="text-lg font-semibold tracking-tight text-slate-100">
            BulkAuditAI
          </span>
        </div>
        <p className="mt-1.5 text-xs text-slate-500">
          defensive bug-bounty triage
        </p>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              [
                'block rounded-md px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-emerald-500/10 text-emerald-400'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200',
              ].join(' ')
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="px-3 py-3 border-t border-slate-800">
        <div className="px-1 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
          Theme
        </div>
        <ThemePicker />
      </div>

      <div className="px-5 py-4 border-t border-slate-800 text-xs text-slate-600">
        Local-only · :8791 backend
      </div>
    </aside>
  )
}
