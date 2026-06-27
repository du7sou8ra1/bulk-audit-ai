import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, type DashboardData } from '../api'
import { PageHeader, Spinner, ErrorBox, EmptyState, fmtDate } from '../components/ui'
import StatusBadge from '../components/StatusBadge'

interface StatCardProps {
  label: string
  value: number
  accent?: string
}

function StatCard({ label, value, accent }: StatCardProps) {
  return (
    <div className="card p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className={`mt-2 text-3xl font-semibold ${accent || 'text-slate-100'}`}>
        {value}
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    let active = true
    api
      .getDashboard()
      .then((d) => active && setData(d))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false))
    return () => {
      active = false
    }
  }, [])

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle="Bulk smart-contract audit overview"
        actions={
          <>
            <Link to="/scans" className="btn-secondary">
              All Scans
            </Link>
            <Link to="/scans/new" className="btn-primary">
              New Scan
            </Link>
          </>
        }
      />

      {loading && <Spinner />}
      {error && <ErrorBox message={error} />}

      {data && (
        <>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
            <StatCard label="Total scans" value={data.total_scans} />
            <StatCard
              label="Running"
              value={data.running_scans}
              accent="text-blue-400"
            />
            <StatCard
              label="Completed"
              value={data.completed_scans}
              accent="text-emerald-400"
            />
            <StatCard
              label="Critical candidates"
              value={data.critical_candidates}
              accent="text-red-400"
            />
            <StatCard
              label="Needs investigation"
              value={data.needs_investigation}
              accent="text-amber-400"
            />
            <StatCard
              label="False positives"
              value={data.false_positives}
              accent="text-zinc-500"
            />
          </div>

          <div className="mt-8 mb-3 flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
              Recent scans
            </h2>
            {data.total_scans > data.recent_scans.length && (
              <Link to="/scans" className="text-sm text-emerald-400 hover:underline">
                View all {data.total_scans}
              </Link>
            )}
          </div>

          {data.recent_scans.length === 0 ? (
            <EmptyState>
              No scans yet.{' '}
              <Link to="/scans/new" className="text-emerald-400 hover:underline">
                Start your first scan
              </Link>
              .
            </EmptyState>
          ) : (
            <div className="card overflow-hidden">
              <table className="w-full">
                <thead className="border-b border-slate-800 bg-slate-900/80">
                  <tr>
                    <th className="th">Name</th>
                    <th className="th">Status</th>
                    <th className="th">Profile</th>
                    <th className="th">Targets</th>
                    <th className="th">Critical</th>
                    <th className="th">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {data.recent_scans.map((scan) => (
                    <tr
                      key={scan.id}
                      onClick={() => navigate(`/scans/${scan.id}`)}
                      className="cursor-pointer hover:bg-slate-800/40"
                    >
                      <td className="td font-medium text-slate-100">
                        {scan.name}
                      </td>
                      <td className="td">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="td text-slate-400">{scan.scan_profile}</td>
                      <td className="td">
                        {scan.completed_targets}/{scan.total_targets}
                      </td>
                      <td className="td text-red-400">{scan.critical_count}</td>
                      <td className="td text-slate-400">
                        {fmtDate(scan.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  )
}
