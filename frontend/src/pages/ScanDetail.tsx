import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  api,
  openScanSocket,
  type ProtocolGraph,
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
import SeverityBadge from '../components/SeverityBadge'

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

interface TargetFindingSummary {
  total: number
  critical: number
  needs: number
  low: number
  falsePositive: number
  maxImpact: number
  maxConfidence: number
  topDetector: string
}

function emptySummary(): TargetFindingSummary {
  return {
    total: 0,
    critical: 0,
    needs: 0,
    low: 0,
    falsePositive: 0,
    maxImpact: 0,
    maxConfidence: 0,
    topDetector: '—',
  }
}

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

function displayTargetName(target: Target | undefined): string {
  if (!target) return 'Unknown contract'
  return target.contract_name || target.label || shortAddr(target.address)
}

function scoreTone(value: number): string {
  if (value >= 8) return 'bg-red-500'
  if (value >= 6) return 'bg-amber-400'
  if (value >= 3) return 'bg-sky-400'
  return 'bg-slate-500'
}

function MiniStat({
  label,
  value,
  tone = 'text-slate-100',
}: {
  label: string
  value: string | number
  tone?: string
}) {
  return (
    <div className="min-w-0 rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2">
      <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className={`mt-1 truncate text-sm font-semibold ${tone}`}>
        {value}
      </div>
    </div>
  )
}

function ScoreBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, value * 10))
  return (
    <div className="min-w-[6rem]">
      <div className="mb-1 flex items-center justify-between gap-2 text-xs">
        <span className="font-medium text-slate-200">
          {value ? value.toFixed(1) : '—'}
        </span>
        <span className="text-slate-500">/ 10</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full rounded-full ${scoreTone(value)}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}

function FocusBadge({
  summary,
}: {
  summary: TargetFindingSummary
}) {
  if (summary.critical > 0) {
    return (
      <span className="rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-300">
        {summary.critical} critical
      </span>
    )
  }
  if (summary.needs > 0) {
    return (
      <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-300">
        {summary.needs} investigate
      </span>
    )
  }
  if (summary.total > 0) {
    return (
      <span className="rounded-full border border-slate-600 bg-slate-800/70 px-2 py-0.5 text-xs font-medium text-slate-300">
        {summary.total} low/info
      </span>
    )
  }
  return (
    <span className="rounded-full border border-slate-800 bg-slate-950 px-2 py-0.5 text-xs text-slate-500">
      clean
    </span>
  )
}

function scanGraphSurfaces(graph: ProtocolGraph | undefined) {
  return Array.isArray(graph?.surfaces) ? graph.surfaces : []
}

function scanGraphCandidates(graph: ProtocolGraph | undefined) {
  return Array.isArray(graph?.companion_scan_candidates)
    ? graph.companion_scan_candidates
    : []
}

function ScanProtocolGraphPanel({ graph }: { graph?: ProtocolGraph }) {
  const surfaces = scanGraphSurfaces(graph)
  const candidates = scanGraphCandidates(graph)
  const summary = graph?.summary ?? {}
  if (surfaces.length === 0 && candidates.length === 0) return null

  return (
    <div className="card p-4 mb-6">
      <div className="mb-3 flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
            Protocol graph
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Cross-contract roles inferred from source, ABI, proxy data, and safe getters.
          </p>
        </div>
        <div className="grid grid-cols-3 gap-2">
          <MiniStat label="Surfaces" value={Number(summary.surface_count ?? surfaces.length)} />
          <MiniStat label="Companions" value={Number(summary.companion_candidate_count ?? candidates.length)} />
          <MiniStat label="Scanned" value={Number(summary.already_scanned_companions ?? 0)} />
        </div>
      </div>

      {surfaces.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-2">
          {surfaces.slice(0, 8).map((surface, idx) => (
            <span
              key={`${surface.id}-${surface.target_address ?? idx}`}
              className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-xs text-amber-200"
              title={surface.next || surface.title || surface.id}
            >
              {surface.id.replace(/_/g, ' ')}
              {surface.target_address && (
                <span className="ml-1 text-slate-400">{shortAddr(surface.target_address)}</span>
              )}
            </span>
          ))}
        </div>
      )}

      {candidates.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px]">
            <thead className="border-b border-slate-800">
              <tr>
                <th className="th">Role</th>
                <th className="th">Component</th>
                <th className="th">Address</th>
                <th className="th">State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {candidates.slice(0, 8).map((candidate, idx) => (
                <tr key={`${candidate.role}-${candidate.label}-${idx}`}>
                  <td className="td text-slate-300">{(candidate.role || 'unknown').replace(/_/g, ' ')}</td>
                  <td className="td text-slate-400">{candidate.label || '—'}</td>
                  <td className="td font-mono text-slate-400">
                    {candidate.address ? shortAddr(candidate.address) : 'unresolved'}
                  </td>
                  <td className="td">
                    {candidate.already_in_scan ? (
                      <span className="text-emerald-300">in scan</span>
                    ) : candidate.address ? (
                      <span className="text-amber-300">scan next</span>
                    ) : (
                      <span className="text-slate-500">needs getter/source</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
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
  const [searchParams, setSearchParams] = useSearchParams()
  const [scan, setScan] = useState<ScanWithTargets | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [logs, setLogs] = useState<LogLine[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [usingWs, setUsingWs] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [rescanning, setRescanning] = useState(false)
  const [targetQuery, setTargetQuery] = useState('')
  const [targetSort, setTargetSort] = useState<TargetSortKey>('findings')
  const [targetSortDir, setTargetSortDir] = useState<SortDir>('desc')
  const [findingQuery, setFindingQuery] = useState('')
  const [contractFilter, setContractFilter] = useState(
    searchParams.get('target') ?? 'all',
  )
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

  useEffect(() => {
    const target = searchParams.get('target') ?? 'all'
    setContractFilter((current) => (current === target ? current : target))
  }, [searchParams])

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

  async function rescan() {
    setRescanning(true)
    try {
      const next = await api.rescanScan(id)
      navigate(`/scans/${next.id}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setRescanning(false)
    }
  }

  const activeTargets = useMemo(() => scan?.targets ?? [], [scan?.targets])

  const targetSummaries = useMemo(() => {
    const rows: Record<string, TargetFindingSummary> = {}
    const detectorCounts: Record<string, Record<string, number>> = {}
    for (const t of activeTargets) {
      rows[t.id] = emptySummary()
      detectorCounts[t.id] = {}
    }
    for (const f of findings) {
      const summary = rows[f.target_id] ?? emptySummary()
      rows[f.target_id] = summary
      detectorCounts[f.target_id] = detectorCounts[f.target_id] ?? {}
      summary.total += 1
      summary.maxImpact = Math.max(summary.maxImpact, f.impact_score ?? 0)
      summary.maxConfidence = Math.max(summary.maxConfidence, f.confidence_score ?? 0)
      detectorCounts[f.target_id][f.detector] =
        (detectorCounts[f.target_id][f.detector] ?? 0) + 1

      if (
        f.classification === 'CONFIRMED_CRITICAL' ||
        f.classification === 'LIKELY_CRITICAL_NEEDS_POC'
      ) {
        summary.critical += 1
      } else if (f.classification === 'NEEDS_MORE_INVESTIGATION') {
        summary.needs += 1
      } else if (f.classification === 'FALSE_POSITIVE') {
        summary.falsePositive += 1
      } else {
        summary.low += 1
      }
    }

    for (const [targetId, counts] of Object.entries(detectorCounts)) {
      const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0]
      if (top) rows[targetId].topDetector = top[0]
    }

    return rows
  }, [activeTargets, findings])

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

  const selectedTarget = contractFilter === 'all' ? null : targetById[contractFilter]

  const visibleTargetSummaries = useMemo(
    () =>
      activeTargets
        .map((target) => ({
          target,
          summary: targetSummaries[target.id] ?? emptySummary(),
        }))
        .sort((a, b) => {
          if (b.summary.critical !== a.summary.critical) {
            return b.summary.critical - a.summary.critical
          }
          if (b.summary.total !== a.summary.total) {
            return b.summary.total - a.summary.total
          }
          return displayTargetName(a.target).localeCompare(displayTargetName(b.target))
        }),
    [activeTargets, targetSummaries],
  )

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

  const filteredSummary = useMemo(() => {
    return filteredFindings.reduce(
      (acc, finding) => {
        acc.total += 1
        acc.maxImpact = Math.max(acc.maxImpact, finding.impact_score ?? 0)
        acc.maxConfidence = Math.max(acc.maxConfidence, finding.confidence_score ?? 0)
        if (
          finding.classification === 'CONFIRMED_CRITICAL' ||
          finding.classification === 'LIKELY_CRITICAL_NEEDS_POC'
        ) {
          acc.critical += 1
        } else if (finding.classification === 'NEEDS_MORE_INVESTIGATION') {
          acc.needs += 1
        } else if (finding.classification === 'FALSE_POSITIVE') {
          acc.falsePositive += 1
        } else {
          acc.low += 1
        }
        return acc
      },
      emptySummary(),
    )
  }, [filteredFindings])

  const detectorBreakdown = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const f of filteredFindings) counts[f.detector] = (counts[f.detector] ?? 0) + 1
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
  }, [filteredFindings])

  function setFocusedTarget(targetId: string) {
    setContractFilter(targetId)
    const next = new URLSearchParams(searchParams)
    if (targetId === 'all') {
      next.delete('target')
    } else {
      next.set('target', targetId)
    }
    setSearchParams(next)
  }

  if (loading) return <Spinner label="Loading scan…" />
  if (error && !scan) return <ErrorBox message={error} />
  if (!scan) return <ErrorBox message="Scan not found." />

  const pct =
    scan.total_targets > 0
      ? Math.round((scan.completed_targets / scan.total_targets) * 100)
      : 0
  const isRunning = scan.status === 'running' || scan.status === 'queued'
  const canRescan = scan.status === 'failed' || scan.status === 'cancelled'

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
    setFocusedTarget('all')
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
            {canRescan && (
              <button
                className="btn-primary"
                onClick={rescan}
                disabled={rescanning}
              >
                {rescanning ? 'Starting...' : 'Rescan'}
              </button>
            )}
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

      <ScanProtocolGraphPanel graph={scan.protocol_graph} />

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
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
            Contracts ({sortedTargets.length} / {activeTargets.length})
          </h2>
          {selectedTarget && (
            <div className="mt-1 text-xs text-emerald-300">
              Focused: {displayTargetName(selectedTarget)}
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          {contractFilter !== 'all' && (
            <button
              type="button"
              className="btn-secondary py-1.5 text-xs"
              onClick={() => setFocusedTarget('all')}
            >
              View all
            </button>
          )}
          <input
            className="input w-64"
            value={targetQuery}
            onChange={(e) => setTargetQuery(e.target.value)}
            placeholder="Filter contracts"
          />
        </div>
      </div>
      <div className="card mb-8 overflow-x-auto">
        <table className="w-full min-w-[960px]">
          <thead className="border-b border-slate-800 bg-slate-900/80">
            <tr>
              <th className="th">
                <SortButton
                  label="Contract"
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
              <th className="th">Top Detector</th>
              <th className="th">Max Impact</th>
              <th className="th">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {sortedTargets.map((t) => {
              const summary = targetSummaries[t.id] ?? emptySummary()
              const focused = contractFilter === t.id
              return (
                <tr
                  key={t.id}
                  className={`cursor-pointer focus-within:bg-slate-800/50 hover:bg-slate-800/40 ${
                    focused ? 'bg-emerald-500/10 ring-1 ring-inset ring-emerald-500/30' : ''
                  }`}
                  onClick={() => setFocusedTarget(t.id)}
                >
                  <td className="td">
                    <div className="flex min-w-0 items-start gap-3">
                      <div className="min-w-0">
                        <Link
                          to={`/targets/${t.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="font-mono text-emerald-400 hover:underline"
                        >
                          {shortAddr(t.address)}
                        </Link>
                        <div className="mt-1 flex flex-wrap items-center gap-2">
                          {t.contract_name && (
                            <span className="truncate text-xs text-slate-300">
                              {t.contract_name}
                            </span>
                          )}
                          {t.label && (
                            <span className="truncate text-xs text-slate-500">
                              {t.label}
                            </span>
                          )}
                        </div>
                      </div>
                      <FocusBadge summary={summary} />
                    </div>
                  </td>
                  <td className="td">
                    <StatusBadge status={t.status} />
                  </td>
                  <td className="td text-slate-400">
                    {t.is_proxy ? t.proxy_type || 'proxy' : '—'}
                  </td>
                  <td className="td">
                    <span className="text-base font-semibold text-slate-100">
                      {summary.total}
                    </span>
                    <span className="ml-2 text-xs text-slate-500">
                      {summary.falsePositive > 0
                        ? `${summary.falsePositive} FP`
                        : 'reviewable'}
                    </span>
                  </td>
                  <td className="td max-w-[13rem] truncate font-mono text-xs text-slate-400">
                    {summary.topDetector}
                  </td>
                  <td className="td">
                    <ScoreBar value={summary.maxImpact} />
                  </td>
                  <td className="td">
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        className={focused ? 'btn-primary py-1.5 text-xs' : 'btn-secondary py-1.5 text-xs'}
                        onClick={(e) => {
                          e.stopPropagation()
                          setFocusedTarget(t.id)
                        }}
                      >
                        Focus
                      </button>
                      <Link
                        to={`/targets/${t.id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="btn-secondary py-1.5 text-xs"
                      >
                        Open
                      </Link>
                    </div>
                  </td>
                </tr>
              )
            })}
            {sortedTargets.length === 0 && (
              <tr>
                <td className="td text-slate-500" colSpan={7}>
                  No matching contracts.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Findings */}
      <div className="mb-2 flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
            Findings ({filteredFindings.length} / {findings.length})
          </h2>
          {selectedTarget && (
            <div className="mt-1 font-mono text-xs text-slate-500">
              {selectedTarget.address}
            </div>
          )}
        </div>
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
          <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_24rem]">
            <div className="card p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <div>
                  <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    Finding View
                  </div>
                  <div className="mt-1 text-base font-semibold text-slate-100">
                    {selectedTarget ? displayTargetName(selectedTarget) : 'All contracts'}
                  </div>
                </div>
                <FocusBadge summary={filteredSummary} />
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                <MiniStat label="Critical" value={filteredSummary.critical} tone="text-red-300" />
                <MiniStat label="Investigate" value={filteredSummary.needs} tone="text-amber-300" />
                <MiniStat label="Low / Info" value={filteredSummary.low} tone="text-slate-300" />
                <MiniStat label="False Positive" value={filteredSummary.falsePositive} tone="text-zinc-400" />
              </div>
              <div className="mt-4 grid gap-4 md:grid-cols-2">
                <div>
                  <div className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
                    Max Impact
                  </div>
                  <ScoreBar value={filteredSummary.maxImpact} />
                </div>
                <div>
                  <div className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
                    Max Confidence
                  </div>
                  <ScoreBar value={filteredSummary.maxConfidence} />
                </div>
              </div>
              {detectorBreakdown.length > 0 && (
                <div className="mt-4 space-y-2">
                  <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    Detector Mix
                  </div>
                  {detectorBreakdown.map(([detector, count]) => (
                    <div key={detector} className="grid grid-cols-[minmax(0,1fr)_3rem] items-center gap-3">
                      <div>
                        <div className="mb-1 truncate font-mono text-xs text-slate-400">
                          {detector}
                        </div>
                        <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
                          <div
                            className="h-full rounded-full bg-emerald-400"
                            style={{
                              width: `${Math.max(6, (count / filteredFindings.length) * 100)}%`,
                            }}
                          />
                        </div>
                      </div>
                      <div className="text-right text-xs font-semibold text-slate-300">
                        {count}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="card p-3">
              <div className="mb-2 flex items-center justify-between">
                <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Contract Focus
                </div>
                {contractFilter !== 'all' && (
                  <button
                    type="button"
                    className="text-xs text-emerald-400 hover:underline"
                    onClick={() => setFocusedTarget('all')}
                  >
                    All
                  </button>
                )}
              </div>
              <div className="space-y-2">
                {visibleTargetSummaries.slice(0, 8).map(({ target, summary }) => {
                  const focused = contractFilter === target.id
                  return (
                    <button
                      key={target.id}
                      type="button"
                      className={`w-full rounded-md border px-3 py-2 text-left transition ${
                        focused
                          ? 'border-emerald-500/50 bg-emerald-500/10'
                          : 'border-slate-800 bg-slate-950/50 hover:border-slate-700 hover:bg-slate-800/40'
                      }`}
                      onClick={() => setFocusedTarget(target.id)}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="truncate text-sm font-medium text-slate-200">
                          {displayTargetName(target)}
                        </span>
                        <span className="text-xs font-semibold text-slate-300">
                          {summary.total}
                        </span>
                      </div>
                      <div className="mt-1 flex items-center justify-between gap-3">
                        <span className="truncate font-mono text-[11px] text-slate-500">
                          {shortAddr(target.address)}
                        </span>
                        <FocusBadge summary={summary} />
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>
          </div>

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
                  onChange={(e) => setFocusedTarget(e.target.value)}
                >
                  <option value="all">All contracts</option>
                  {visibleTargetSummaries.map(({ target, summary }) => (
                    <option key={target.id} value={target.id}>
                      {displayTargetName(target)} ({summary.total})
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
            <table className="w-full min-w-[1120px]">
              <thead className="border-b border-slate-800 bg-slate-900/80">
                <tr>
                  <th className="th">
                    <SortButton
                      label="Contract"
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
                      label="Finding"
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
                  <th className="th">Open</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredFindings.map((f) => {
                  const target = targetById[f.target_id]
                  return (
                    <tr
                      key={f.id}
                      className="cursor-pointer hover:bg-slate-800/40"
                      onClick={() => navigate(`/findings/${f.id}`)}
                    >
                      <td className="td">
                        <div className="max-w-[12rem]">
                          <Link
                            to={`/targets/${f.target_id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="font-mono text-xs text-emerald-400 hover:underline"
                          >
                            {shortAddr(addrByTarget[f.target_id] ?? `#${f.target_id}`)}
                          </Link>
                          <button
                            type="button"
                            className="mt-1 block max-w-full truncate text-left text-xs text-slate-500 hover:text-slate-300"
                            onClick={(e) => {
                              e.stopPropagation()
                              setFocusedTarget(f.target_id)
                            }}
                          >
                            {displayTargetName(target)}
                          </button>
                        </div>
                      </td>
                      <td className="td max-w-[12rem] truncate font-mono text-xs text-slate-400">
                        {f.detector}
                      </td>
                      <td className="td">
                        <div className="max-w-[22rem]">
                          <Link
                            to={`/findings/${f.id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="text-slate-100 hover:text-emerald-400 hover:underline"
                          >
                            {f.title}
                          </Link>
                          <div className="mt-1 flex flex-wrap items-center gap-2">
                            <SeverityBadge severity={f.severity_candidate} />
                            <span className="text-xs text-slate-500">
                              #{f.id}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="td">
                        <ScoreBar value={f.impact_score ?? 0} />
                      </td>
                      <td className="td">
                        <ScoreBar value={f.confidence_score ?? 0} />
                      </td>
                      <td className="td">
                        <ClassificationBadge classification={f.classification} />
                      </td>
                      <td className="td text-slate-400">{f.status}</td>
                      <td className="td max-w-[16rem] truncate text-xs text-slate-400">
                        {firstNextTest(f)}
                      </td>
                      <td className="td">
                        <Link
                          to={`/findings/${f.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="btn-secondary py-1.5 text-xs"
                        >
                          Open
                        </Link>
                      </td>
                    </tr>
                  )
                })}
                {filteredFindings.length === 0 && (
                  <tr>
                    <td className="td text-slate-500" colSpan={9}>
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
