import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, type Scan, type ScanStatus } from '../api'
import {
  PageHeader,
  Spinner,
  ErrorBox,
  EmptyState,
  fmtDate,
} from '../components/ui'
import StatusBadge from '../components/StatusBadge'

type SortKey =
  | 'created_at'
  | 'name'
  | 'status'
  | 'chain'
  | 'profile'
  | 'targets'
  | 'critical'
  | 'needs'
type SortDir = 'asc' | 'desc'

function textValue(value: unknown): string {
  return String(value ?? '').toLowerCase()
}

function optionLabel(value: string): string {
  return value.replace(/-/g, ' ').replace(/\b\w/g, (m: string) => m.toUpperCase())
}

function SortButton({
  label,
  active,
  dir,
  onClick,
}: {
  label: string
  active: boolean
  dir: SortDir
  onClick: () => void
}) {
  return (
    <button
      type="button"
      className={`inline-flex items-center gap-1 text-left uppercase tracking-wide ${
        active ? 'text-emerald-300' : 'text-slate-400 hover:text-slate-200'
      }`}
      onClick={onClick}
    >
      <span>{label}</span>
      <span className="text-[10px]">{active ? dir : 'sort'}</span>
    </button>
  )
}

export default function ScansHistory() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | ScanStatus>('all')
  const [chainFilter, setChainFilter] = useState('all')
  const [profileFilter, setProfileFilter] = useState('all')
  const [sortKey, setSortKey] = useState<SortKey>('created_at')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const navigate = useNavigate()

  useEffect(() => {
    let active = true
    api
      .listScans()
      .then((rows) => {
        if (active) setScans(rows)
      })
      .catch((e) => {
        if (active) setError(e instanceof Error ? e.message : String(e))
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [])

  const chainOptions = useMemo(
    () => Array.from(new Set(scans.map((s) => s.chain))).sort(),
    [scans],
  )
  const profileOptions = useMemo(
    () => Array.from(new Set(scans.map((s) => s.scan_profile))).sort(),
    [scans],
  )
  const statusOptions = useMemo(
    () => Array.from(new Set(scans.map((s) => s.status))).sort() as ScanStatus[],
    [scans],
  )

  const filteredScans = useMemo(() => {
    const q = textValue(query)
    const rows = scans.filter((scan) => {
      if (statusFilter !== 'all' && scan.status !== statusFilter) return false
      if (chainFilter !== 'all' && scan.chain !== chainFilter) return false
      if (profileFilter !== 'all' && scan.scan_profile !== profileFilter) return false
      if (!q) return true
      return [
        scan.id,
        scan.name,
        scan.status,
        scan.chain,
        scan.scan_profile,
        scan.error,
      ].some((v) => textValue(v).includes(q))
    })

    const dir = sortDir === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      let av: string | number = ''
      let bv: string | number = ''
      if (sortKey === 'created_at') {
        av = new Date(a.created_at).getTime()
        bv = new Date(b.created_at).getTime()
      } else if (sortKey === 'name') {
        av = a.name
        bv = b.name
      } else if (sortKey === 'status') {
        av = a.status
        bv = b.status
      } else if (sortKey === 'chain') {
        av = a.chain
        bv = b.chain
      } else if (sortKey === 'profile') {
        av = a.scan_profile
        bv = b.scan_profile
      } else if (sortKey === 'targets') {
        av = a.total_targets
        bv = b.total_targets
      } else if (sortKey === 'critical') {
        av = a.critical_count
        bv = b.critical_count
      } else {
        av = a.needs_investigation_count
        bv = b.needs_investigation_count
      }
      if (typeof av === 'number' && typeof bv === 'number') {
        return (av - bv) * dir
      }
      return String(av).localeCompare(String(bv)) * dir
    })
  }, [scans, query, statusFilter, chainFilter, profileFilter, sortKey, sortDir])

  function setSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir(
        key === 'created_at' ||
          key === 'targets' ||
          key === 'critical' ||
          key === 'needs'
          ? 'desc'
          : 'asc',
      )
    }
  }

  function resetFilters() {
    setQuery('')
    setStatusFilter('all')
    setChainFilter('all')
    setProfileFilter('all')
    setSortKey('created_at')
    setSortDir('desc')
  }

  const activeCount = scans.filter(
    (s) => s.status === 'queued' || s.status === 'running',
  ).length

  return (
    <div>
      <PageHeader
        title="All scans"
        subtitle={`${scans.length} total scans, ${activeCount} active`}
        actions={
          <>
            <button className="btn-secondary" onClick={resetFilters}>
              Reset
            </button>
            <Link to="/scans/new" className="btn-primary">
              New Scan
            </Link>
          </>
        }
      />

      {loading && <Spinner label="Loading scan history..." />}
      {error && <ErrorBox message={error} />}

      {!loading && !error && scans.length === 0 && (
        <EmptyState>
          No scans yet.{' '}
          <Link to="/scans/new" className="text-emerald-400 hover:underline">
            Start your first scan
          </Link>
          .
        </EmptyState>
      )}

      {scans.length > 0 && (
        <div className="space-y-3">
          <div className="card p-3">
            <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-[2fr_1fr_1fr_1fr]">
              <div>
                <label className="label" htmlFor="scan-history-search">
                  Search
                </label>
                <input
                  id="scan-history-search"
                  className="input"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Name, id, chain, profile, error"
                />
              </div>
              <div>
                <label className="label" htmlFor="scan-status-filter">
                  Status
                </label>
                <select
                  id="scan-status-filter"
                  className="input"
                  value={statusFilter}
                  onChange={(e) =>
                    setStatusFilter(e.target.value as 'all' | ScanStatus)
                  }
                >
                  <option value="all">All statuses</option>
                  {statusOptions.map((s) => (
                    <option key={s} value={s}>
                      {optionLabel(s)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label" htmlFor="scan-chain-filter">
                  Chain
                </label>
                <select
                  id="scan-chain-filter"
                  className="input"
                  value={chainFilter}
                  onChange={(e) => setChainFilter(e.target.value)}
                >
                  <option value="all">All chains</option>
                  {chainOptions.map((chain) => (
                    <option key={chain} value={chain}>
                      {optionLabel(chain)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label" htmlFor="scan-profile-filter">
                  Profile
                </label>
                <select
                  id="scan-profile-filter"
                  className="input"
                  value={profileFilter}
                  onChange={(e) => setProfileFilter(e.target.value)}
                >
                  <option value="all">All profiles</option>
                  {profileOptions.map((profile) => (
                    <option key={profile} value={profile}>
                      {optionLabel(profile)}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          <div className="mb-2 text-sm text-slate-500">
            Showing {filteredScans.length} of {scans.length} scans.
          </div>

          <div className="card overflow-x-auto">
            <table className="w-full min-w-[980px]">
              <thead className="border-b border-slate-800 bg-slate-900/80">
                <tr>
                  <th className="th">
                    <SortButton
                      label="Name"
                      active={sortKey === 'name'}
                      dir={sortDir}
                      onClick={() => setSort('name')}
                    />
                  </th>
                  <th className="th">
                    <SortButton
                      label="Status"
                      active={sortKey === 'status'}
                      dir={sortDir}
                      onClick={() => setSort('status')}
                    />
                  </th>
                  <th className="th">
                    <SortButton
                      label="Chain"
                      active={sortKey === 'chain'}
                      dir={sortDir}
                      onClick={() => setSort('chain')}
                    />
                  </th>
                  <th className="th">
                    <SortButton
                      label="Profile"
                      active={sortKey === 'profile'}
                      dir={sortDir}
                      onClick={() => setSort('profile')}
                    />
                  </th>
                  <th className="th">
                    <SortButton
                      label="Targets"
                      active={sortKey === 'targets'}
                      dir={sortDir}
                      onClick={() => setSort('targets')}
                    />
                  </th>
                  <th className="th">
                    <SortButton
                      label="Critical"
                      active={sortKey === 'critical'}
                      dir={sortDir}
                      onClick={() => setSort('critical')}
                    />
                  </th>
                  <th className="th">
                    <SortButton
                      label="Needs"
                      active={sortKey === 'needs'}
                      dir={sortDir}
                      onClick={() => setSort('needs')}
                    />
                  </th>
                  <th className="th">
                    <SortButton
                      label="Created"
                      active={sortKey === 'created_at'}
                      dir={sortDir}
                      onClick={() => setSort('created_at')}
                    />
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredScans.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => navigate(`/scans/${scan.id}`)}
                    className="cursor-pointer hover:bg-slate-800/40"
                  >
                    <td className="td">
                      <Link
                        to={`/scans/${scan.id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="font-medium text-slate-100 hover:text-emerald-400 hover:underline"
                      >
                        {scan.name}
                      </Link>
                      <div className="mt-1 font-mono text-[11px] text-slate-600">
                        #{scan.id}
                      </div>
                    </td>
                    <td className="td">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="td text-slate-400">{scan.chain}</td>
                    <td className="td text-slate-400">{scan.scan_profile}</td>
                    <td className="td">
                      {scan.completed_targets}/{scan.total_targets}
                    </td>
                    <td className="td text-red-400">{scan.critical_count}</td>
                    <td className="td text-amber-400">
                      {scan.needs_investigation_count}
                    </td>
                    <td className="td text-slate-400">
                      {fmtDate(scan.created_at)}
                    </td>
                  </tr>
                ))}
                {filteredScans.length === 0 && (
                  <tr>
                    <td className="td text-slate-500" colSpan={8}>
                      No scans match the current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
