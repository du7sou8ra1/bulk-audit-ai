import { useEffect, useRef, useState, useCallback } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  api,
  openScanSocket,
  type ScanWithTargets,
  type Finding,
  type ScanEvent,
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

export default function ScanDetail() {
  const { id = '' } = useParams()
  const [scan, setScan] = useState<ScanWithTargets | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [logs, setLogs] = useState<LogLine[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [usingWs, setUsingWs] = useState(false)
  const [cancelling, setCancelling] = useState(false)

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

  if (loading) return <Spinner label="Loading scan…" />
  if (error && !scan) return <ErrorBox message={error} />
  if (!scan) return <ErrorBox message="Scan not found." />

  const pct =
    scan.total_targets > 0
      ? Math.round((scan.completed_targets / scan.total_targets) * 100)
      : 0
  const isRunning = scan.status === 'running' || scan.status === 'queued'

  const findingsByTarget: Record<string, number> = {}
  for (const f of findings) {
    findingsByTarget[f.target_id] = (findingsByTarget[f.target_id] || 0) + 1
  }

  // Findings carry a numeric target_id, not an address — resolve the real
  // contract address from the scan's target list for display.
  const addrByTarget: Record<string, string> = {}
  for (const t of scan.targets) addrByTarget[t.id] = t.address

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
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
        Targets ({scan.targets.length})
      </h2>
      <div className="card mb-8 overflow-hidden">
        <table className="w-full">
          <thead className="border-b border-slate-800 bg-slate-900/80">
            <tr>
              <th className="th">Address</th>
              <th className="th">Status</th>
              <th className="th">Proxy</th>
              <th className="th">Findings</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {scan.targets.map((t) => (
              <tr key={t.id} className="hover:bg-slate-800/40">
                <td className="td">
                  <Link
                    to={`/targets/${t.id}`}
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
            {scan.targets.length === 0 && (
              <tr>
                <td className="td text-slate-500" colSpan={4}>
                  No targets.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Findings */}
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
        Findings ({findings.length})
      </h2>
      {findings.length === 0 ? (
        <EmptyState>
          No findings yet{isRunning ? ' — scan still running.' : '.'}
        </EmptyState>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[900px]">
            <thead className="border-b border-slate-800 bg-slate-900/80">
              <tr>
                <th className="th">Address</th>
                <th className="th">Detector</th>
                <th className="th">Title</th>
                <th className="th">Impact</th>
                <th className="th">Conf.</th>
                <th className="th">AI Classification</th>
                <th className="th">Status</th>
                <th className="th">Next Test</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {findings.map((f) => (
                <tr key={f.id} className="hover:bg-slate-800/40">
                  <td className="td">
                    <Link
                      to={`/targets/${f.target_id}`}
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
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
