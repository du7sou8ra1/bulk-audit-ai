import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  api,
  openScanSocket,
  type ScanWithTargets,
  type Finding,
  type ScanEvent,
  type Target,
} from '../api'
import {
  PageHeader,
  Spinner,
  ErrorBox,
  EmptyState,
  shortAddr,
} from '../components/ui'
import StatusBadge from '../components/StatusBadge'
import ClassificationBadge from '../components/ClassificationBadge'

interface LogLine {
  ts: string
  text: string
}

type FindingSortKey =
  | 'address'
  | 'detector'
  | 'title'
  | 'impact'
  | 'confidence'
  | 'classification'
  | 'status'

type TargetSortKey = 'address' | 'status' | 'proxy' | 'findings'
type SortDir = 'asc' | 'desc'

function firstNextTest(finding: Finding): string {
  const t = finding.next_tests_json
  if (!Array.isArray(t) || t.length === 0) return '—'
  const head = t[0]
  if (typeof head === 'string') return head
  if (head && typeof head === 'object') {
    const obj = head as Record<string, unknown>
    return String(obj.title ?? obj.name ?? obj.test ?? JSON.stringify(head))
  }
  return String(head)
}

function textValue(value: unknown): string {
  return String(value ?? '').toLowerCase()
}

function optionLabel(value: string): string {
  return value
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (m: string) => m.toUpperCase())
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
      <span className="text-[10px]">{active ? (dir === 'asc' ? '▲' : '▼') : '↕'}</span>
    </button>
  )
}

export default function ScanDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState<ScanWithTargets | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [logs, setLogs] = useState<LogLine[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [usingWs, setUsingWs] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [targetQuery, setTargetQuery] = useState('')
  const [targetSort, setTargetSort] = useState<TargetSortKey>('findings')
  const [targetSortDir, setTargetSortDir] = useState<SortDir>('desc')
  const [findingQuery, setFindingQuery] = useState('')
  const [contractFilter, setContractFilter] = useState('all')
  const [detectorFilter, setDetectorFilter] = useState('all')
  const [classificationFilter, setClassificationFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [hideFalsePositives, setHideFalsePositives] = useState(false)
  const [findingSort, setFindingSort] = useState<FindingSortKey>('impact')
  const [findingSortDir, setFindingSortDir] = useState<SortDir>('desc')

  const logEndRef = useRef<HTMLDivElement | null>(null)
  const pollRef = useRef<number | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [s, f] = await Promise.all([
        api.getScan(id),
        api.getScanFindings(id).catch(() => [] as Finding[]),
      ])
      setScan(s)
      setFindings(f)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [id])

  // Initial load
  useEffect(() => {
    void refresh()
  }, [refresh])

  // Live updates: WebSocket with polling fallback
  useEffect(() => {
    if (!id) return
    let ws: WebSocket | null = null
    let cancelled = false

    const startPolling = () => {
      if (pollRef.current != null) return
      pollRef.current = window.setInterval(() => {
        void refresh()
      }, 3000)
    }
    const stopPolling = () => {
      if (pollRef.current != null) {
        window.clearInterval(pollRef.current)
        pollRef.current = null
      }
    }

    const onMessage = (ev: ScanEvent) => {
      if (cancelled) return
      if (ev.type === 'log') {
        const text =
          (ev.message as string) ?? (ev.text as string) ?? JSON.stringify(ev)
        setLogs((prev) =>
          [...prev, { ts: new Date().toLocaleTimeString(), text }].slice(-500),
        )
      }
      // For any structured update, re-fetch authoritative state.
      if (
        ev.type === 'scan_update' ||
        ev.type === 'target_update' ||
        ev.type === 'tool_update'
      ) {
        void refresh()
      }
    }

    ws = openScanSocket(
      id,
      onMessage,
      () => {
        // socket error -> fall back to polling
        setUsingWs(false)
        startPolling()
      },
    )

    if (ws) {
      ws.onopen = () => {
        if (!cancelled) setUsingWs(true)
      }
      ws.onclose = () => {
        if (!cancelled) {
          setUsingWs(false)
          startPolling()
        }
      }
    } else {
      startPolling()
    }

    return () => {
      cancelled = true
      stopPolling()
      if (ws) {
        ws.onclose = null
        ws.close()
      }
    }
  }, [id, refresh])

  // Auto-scroll log panel
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  async function cancel() {
    setCancelling(true)
    try {
      await api.cancelScan(id)
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setCancelling(false)
    }
  }

  const activeTargets = useMemo(() => scan?.targets ?? [], [scan?.targets])

  const findingsByTarget = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const f of findings) {
      counts[f.target_id] = (counts[f.target_id] || 0) + 1
    }
    return counts
  }, [findings])

  // Findings carry a numeric target_id, not an address — resolve the real
  // contract address from the scan's target list for display.
  const addrByTarget = useMemo(() => {
    const rows: Record<string, string> = {}
    for (const t of activeTargets) rows[t.id] = t.address
    return rows
  }, [activeTargets])

  const targetById = useMemo(() => {
    const rows: Record<string, Target> = {}
    for (const t of activeTargets) rows[t.id] = t
    return rows
  }, [activeTargets])

  const sortedTargets = useMemo(() => {
    const q = textValue(targetQuery)
    const rows = activeTargets.filter((t) => {
      if (!q) return true
      return [
        t.address,
        t.label,
        t.contract_name,
        t.status,
        t.proxy_type,
      ].some((v) => textValue(v).includes(q))
    })
    const dir = targetSortDir === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      let av: string | number = ''
      let bv: string | number = ''
      if (targetSort === 'address') {
        av = a.address
        bv = b.address
      } else if (targetSort === 'status') {
        av = a.status
        bv = b.status
      } else if (targetSort === 'proxy') {
        av = a.proxy_type || (a.is_proxy ? 'proxy' : '')
        bv = b.proxy_type || (b.is_proxy ? 'proxy' : '')
      } else {
        av = findingsByTarget[a.id] || 0
        bv = findingsByTarget[b.id] || 0
      }
      if (typeof av === 'number' && typeof bv === 'number') {
        return (av - bv) * dir
      }
      return String(av).localeCompare(String(bv)) * dir
    })
  }, [activeTargets, targetQuery, targetSort, targetSortDir, findingsByTarget])

  const detectorOptions = useMemo(
    () => Array.from(new Set(findings.map((f) => f.detector))).sort(),
    [findings],
  )
  const classificationOptions = useMemo(
    () => Array.from(new Set(findings.map((f) => f.classification))).sort(),
    [findings],
  )
  const statusOptions = useMemo(
    () => Array.from(new Set(findings.map((f) => f.status))).sort(),
    [findings],
  )

  const filteredFindings = useMemo(() => {
    const q = textValue(findingQuery)
    const rows = findings.filter((f) => {
      const address = addrByTarget[f.target_id] ?? ''
      const target = targetById[f.target_id]
      if (contractFilter !== 'all' && f.target_id !== contractFilter) return false
      if (detectorFilter !== 'all' && f.detector !== detectorFilter) return false
      if (classificationFilter !== 'all' && f.classification !== classificationFilter) return false
      if (statusFilter !== 'all' && f.status !== statusFilter) return false
      if (hideFalsePositives && f.classification === 'FALSE_POSITIVE') return false
      if (!q) return true
      return [
        address,
        target?.contract_name,
        target?.label,
        f.detector,
        f.title,
        f.classification,
        f.status,
        firstNextTest(f),
      ].some((v) => textValue(v).includes(q))
    })

    const dir = findingSortDir === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      let av: string | number = ''
      let bv: string | number = ''
      if (findingSort === 'impact') {
        av = a.impact_score ?? -1
        bv = b.impact_score ?? -1
      } else if (findingSort === 'confidence') {
        av = a.confidence_score ?? -1
        bv = b.confidence_score ?? -1
      } else if (findingSort === 'address') {
        av = addrByTarget[a.target_id] ?? ''
        bv = addrByTarget[b.target_id] ?? ''
      } else if (findingSort === 'detector') {
        av = a.detector
        bv = b.detector
      } else if (findingSort === 'classification') {
        av = a.classification
        bv = b.classification
      } else if (findingSort === 'status') {
        av = a.status
        bv = b.status
      } else {
        av = a.title
        bv = b.title
      }
      if (typeof av === 'number' && typeof bv === 'number') {
        return (av - bv) * dir
      }
      return String(av).localeCompare(String(bv)) * dir
    })
  }, [
    findings,
    findingQuery,
    contractFilter,
    detectorFilter,
    classificationFilter,
    statusFilter,
    hideFalsePositives,
    findingSort,
    findingSortDir,
    addrByTarget,
    targetById,
  ])

  if (loading) return <Spinner label="Loading scan…" />
  if (error && !scan) return <ErrorBox message={error} />
  if (!scan) return <ErrorBox message="Scan not found." />

  const pct =
    scan.total_targets > 0
      ? Math.round((scan.completed_targets / scan.total_targets) * 100)
      : 0
  const isRunning = scan.status === 'running' || scan.status === 'queued'

  function setTargetSortColumn(key: TargetSortKey) {
    if (targetSort === key) {
      setTargetSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setTargetSort(key)
      setTargetSortDir(key === 'findings' ? 'desc' : 'asc')
    }
  }

  function setFindingSortColumn(key: FindingSortKey) {
    if (findingSort === key) {
      setFindingSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setFindingSort(key)
      setFindingSortDir(key === 'impact' || key === 'confidence' ? 'desc' : 'asc')
    }
  }

  function resetFindingFilters() {
    setFindingQuery('')
    setContractFilter('all')
    setDetectorFilter('all')
    setClassificationFilter('all')
    setStatusFilter('all')
    setHideFalsePositives(false)
    setFindingSort('impact')
    setFindingSortDir('desc')
  }

  const exportBtn = (fmt: 'json' | 'csv' | 'md' | 'zip', label: string) => (
    <a
      key={fmt}
      href={api.exportScanUrl(id, fmt)}
      target="_blank"
      rel="noreferrer"
      className="btn-secondary"
    >
      {label}
    </a>
  )

  return (
    <div>
      <PageHeader
        title={scan.name}
        subtitle={
          <span className="flex items-center gap-2 flex-wrap">
            <StatusBadge status={scan.status} />
            <span className="text-slate-500">·</span>
            <span className="font-mono text-xs">{scan.chain}</span>
            <span className="text-slate-500">·</span>
            <span>{scan.scan_profile}</span>
            <span className="text-slate-500">·</span>
            <span className="text-xs text-slate-500">
              {usingWs ? 'live (ws)' : 'polling'}
            </span>
          </span>
        }
        actions={
          <div className="flex items-center gap-2">
            {exportBtn('json', 'JSON')}
            {exportBtn('csv', 'CSV')}
            {exportBtn('md', 'Markdown')}
            {exportBtn('zip', 'ZIP')}
            {isRunning && (
              <button
                className="btn-danger"
                onClick={cancel}
                disabled={cancelling}
              >
                {cancelling ? 'Cancelling…' : 'Cancel'}
              </button>
            )}
          </div>
        }
      />

      {scan.error && (
        <div className="mb-4">
          <ErrorBox message={scan.error} />
        </div>
      )}

      {/* Progress */}
      <div className="card p-4 mb-6">
        <div className="flex items-center justify-between text-sm mb-2">
          <span className="text-slate-400">
            {scan.completed_targets} / {scan.total_targets} targets
          </span>
          <span className="text-slate-300 font-medium">{pct}%</span>
        </div>
        <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
          <div
            className="h-full bg-emerald-500 transition-all"
            style={{ width: `${pct}%` }}
          />
        </div>
        <div className="mt-3 flex flex-wrap gap-4 text-xs">
          <span className="text-red-400">
            Critical: {scan.critical_count}
          </span>
          <span className="text-amber-400">
            Needs investigation: {scan.needs_investigation_count}
          </span>
          <span className="text-slate-400">
            Low/info: {scan.low_info_count}
          </span>
          <span className="text-zinc-500">
            False positive: {scan.false_positive_count}
          </span>
        </div>
      </div>

      {/* Live log */}
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
        Live log
      </h2>
      <div className="card mb-6 h-48 overflow-auto bg-slate-950 p-3 font-mono text-xs">
        {logs.length === 0 ? (
          <span className="text-slate-600">
            {isRunning
              ? 'Waiting for log events…'
              : 'No live log events captured for this session.'}
          </span>
        ) : (
          logs.map((l, i) => (
            <div key={i} className="text-slate-400">
              <span className="text-slate-600">{l.ts}</span>{' '}
              <span className="text-slate-300">{l.text}</span>
            </div>
          ))
        )}
        <div ref={logEndRef} />
      </div>

      {/* Targets */}
      <div className="mb-2 flex items-center justify-between gap-3 flex-wrap">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Targets ({sortedTargets.length} / {activeTargets.length})
        </h2>
        <input
          className="input max-w-xs"
          value={targetQuery}
          onChange={(e) => setTargetQuery(e.target.value)}
          placeholder="Filter contracts"
        />
      </div>
      <div className="card mb-8 overflow-hidden">
        <table className="w-full">
          <thead className="border-b border-slate-800 bg-slate-900/80">
            <tr>
              <th className="th">
                <SortButton
                  label="Address"
                  active={targetSort === 'address'}
                  dir={targetSortDir}
                  onClick={() => setTargetSortColumn('address')}
                />
              </th>
              <th className="th">
                <SortButton
                  label="Status"
                  active={targetSort === 'status'}
                  dir={targetSortDir}
                  onClick={() => setTargetSortColumn('status')}
                />
              </th>
              <th className="th">
                <SortButton
                  label="Proxy"
                  active={targetSort === 'proxy'}
                  dir={targetSortDir}
                  onClick={() => setTargetSortColumn('proxy')}
                />
              </th>
              <th className="th">
                <SortButton
                  label="Findings"
                  active={targetSort === 'findings'}
                  dir={targetSortDir}
                  onClick={() => setTargetSortColumn('findings')}
                />
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {sortedTargets.map((t) => (
              <tr
                key={t.id}
                className="hover:bg-slate-800/40 cursor-pointer focus-within:bg-slate-800/40"
                onClick={() => navigate(`/targets/${t.id}`)}
              >
                <td className="td">
                  <Link
                    to={`/targets/${t.id}`}
                    onClick={(e) => e.stopPropagation()}
                    className="font-mono text-emerald-400 hover:underline"
                  >
                    {shortAddr(t.address)}
                  </Link>
                  {t.label && (
                    <span className="ml-2 text-xs text-slate-500">
                      {t.label}
                    </span>
                  )}
                  {t.contract_name && (
                    <span className="ml-2 text-xs text-slate-400">
                      {t.contract_name}
                    </span>
                  )}
                </td>
                <td className="td">
                  <StatusBadge status={t.status} />
                </td>
                <td className="td text-slate-400">
                  {t.is_proxy ? t.proxy_type || 'proxy' : '—'}
                </td>
                <td className="td">{findingsByTarget[t.id] || 0}</td>
              </tr>
            ))}
            {sortedTargets.length === 0 && (
              <tr>
                <td className="td text-slate-500" colSpan={4}>
                  No matching contracts.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Findings */}
      <div className="mb-2 flex items-center justify-between gap-3 flex-wrap">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Findings ({filteredFindings.length} / {findings.length})
        </h2>
        <button className="btn-secondary py-1.5 text-xs" onClick={resetFindingFilters}>
          Reset filters
        </button>
      </div>
      {findings.length === 0 ? (
        <EmptyState>
          No findings yet{isRunning ? ' — scan still running.' : '.'}
        </EmptyState>
      ) : (
        <div className="space-y-3">
          <div className="card p-3">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-6">
              <div className="xl:col-span-2">
                <label className="label" htmlFor="finding-search">
                  Search
                </label>
                <input
                  id="finding-search"
                  className="input"
                  value={findingQuery}
                  onChange={(e) => setFindingQuery(e.target.value)}
                  placeholder="Title, detector, contract, next test"
                />
              </div>
              <div>
                <label className="label" htmlFor="contract-filter">
                  Contract
                </label>
                <select
                  id="contract-filter"
                  className="input"
                  value={contractFilter}
                  onChange={(e) => setContractFilter(e.target.value)}
                >
                  <option value="all">All contracts</option>
                  {activeTargets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.contract_name || t.label || shortAddr(t.address)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label" htmlFor="detector-filter">
                  Detector
                </label>
                <select
                  id="detector-filter"
                  className="input"
                  value={detectorFilter}
                  onChange={(e) => setDetectorFilter(e.target.value)}
                >
                  <option value="all">All detectors</option>
                  {detectorOptions.map((d) => (
                    <option key={d} value={d}>
                      {d}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label" htmlFor="classification-filter">
                  Classification
                </label>
                <select
                  id="classification-filter"
                  className="input"
                  value={classificationFilter}
                  onChange={(e) => setClassificationFilter(e.target.value)}
                >
                  <option value="all">All classifications</option>
                  {classificationOptions.map((c) => (
                    <option key={c} value={c}>
                      {optionLabel(c)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label" htmlFor="status-filter">
                  Status
                </label>
                <select
                  id="status-filter"
                  className="input"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <option value="all">All statuses</option>
                  {statusOptions.map((s) => (
                    <option key={s} value={s}>
                      {optionLabel(s)}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <label className="mt-3 inline-flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-600"
                checked={hideFalsePositives}
                onChange={(e) => setHideFalsePositives(e.target.checked)}
              />
              Hide AI false positives
            </label>
          </div>

          <div className="card overflow-x-auto">
            <table className="w-full min-w-[980px]">
            <thead className="border-b border-slate-800 bg-slate-900/80">
              <tr>
                <th className="th">
                  <SortButton
                    label="Address"
                    active={findingSort === 'address'}
                    dir={findingSortDir}
                    onClick={() => setFindingSortColumn('address')}
                  />
                </th>
                <th className="th">
                  <SortButton
                    label="Detector"
                    active={findingSort === 'detector'}
                    dir={findingSortDir}
                    onClick={() => setFindingSortColumn('detector')}
                  />
                </th>
                <th className="th">
                  <SortButton
                    label="Title"
                    active={findingSort === 'title'}
                    dir={findingSortDir}
                    onClick={() => setFindingSortColumn('title')}
                  />
                </th>
                <th className="th">
                  <SortButton
                    label="Impact"
                    active={findingSort === 'impact'}
                    dir={findingSortDir}
                    onClick={() => setFindingSortColumn('impact')}
                  />
                </th>
                <th className="th">
                  <SortButton
                    label="Conf."
                    active={findingSort === 'confidence'}
                    dir={findingSortDir}
                    onClick={() => setFindingSortColumn('confidence')}
                  />
                </th>
                <th className="th">
                  <SortButton
                    label="AI Classification"
                    active={findingSort === 'classification'}
                    dir={findingSortDir}
                    onClick={() => setFindingSortColumn('classification')}
                  />
                </th>
                <th className="th">
                  <SortButton
                    label="Status"
                    active={findingSort === 'status'}
                    dir={findingSortDir}
                    onClick={() => setFindingSortColumn('status')}
                  />
                </th>
                <th className="th">Next Test</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredFindings.map((f) => (
                <tr
                  key={f.id}
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => navigate(`/findings/${f.id}`)}
                >
                  <td className="td">
                    <Link
                      to={`/targets/${f.target_id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="font-mono text-xs text-emerald-400 hover:underline"
                    >
                      {shortAddr(addrByTarget[f.target_id] ?? `#${f.target_id}`)}
                    </Link>
                  </td>
                  <td className="td font-mono text-xs text-slate-400">
                    {f.detector}
                  </td>
                  <td className="td">
                    <Link
                      to={`/findings/${f.id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="text-slate-100 hover:text-emerald-400 hover:underline"
                    >
                      {f.title}
                    </Link>
                  </td>
                  <td className="td font-medium">
                    {f.impact_score?.toFixed(1) ?? '—'}
                  </td>
                  <td className="td font-medium">
                    {f.confidence_score?.toFixed(1) ?? '—'}
                  </td>
                  <td className="td">
                    <ClassificationBadge classification={f.classification} />
                  </td>
                  <td className="td text-slate-400">{f.status}</td>
                  <td className="td text-xs text-slate-400 max-w-[14rem] truncate">
                    {firstNextTest(f)}
                  </td>
                </tr>
              ))}
              {filteredFindings.length === 0 && (
                <tr>
                  <td className="td text-slate-500" colSpan={8}>
                    No findings match the current filters.
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
