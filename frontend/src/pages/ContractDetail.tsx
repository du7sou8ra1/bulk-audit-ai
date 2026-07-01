import { useEffect, useState, type ReactNode } from 'react'
import { useParams } from 'react-router-dom'
import { api, type ProtocolGraph, type TargetWithDetails, type ToolRun } from '../api'
import {
  PageHeader,
  Spinner,
  ErrorBox,
  EmptyState,
  fmtDate,
  shortAddr,
} from '../components/ui'
import StatusBadge from '../components/StatusBadge'
import FindingCard from '../components/FindingCard'
import ToolOutputViewer from '../components/ToolOutputViewer'
import ProgressTimeline from '../components/ProgressTimeline'

// Map a target's free-form status string onto a pipeline stage id.
function statusToStage(status: string | null | undefined): string | null {
  const s = (status || '').toLowerCase()
  if (!s) return null
  if (s.includes('done') || s.includes('complete') || s === 'ok') return 'done'
  if (s.includes('ai')) return 'ai'
  if (s.includes('tool')) return 'tools'
  if (s.includes('detect')) return 'detect'
  if (s.includes('proxy')) return 'proxy'
  if (s.includes('fetch') || s.includes('queue') || s.includes('pending'))
    return 'fetch'
  if (s.includes('run')) return 'tools'
  return null
}

function InfoRow({
  label,
  value,
  mono,
}: {
  label: string
  value: ReactNode
  mono?: boolean
}) {
  return (
    <div className="flex justify-between gap-4 py-2 border-b border-slate-800 last:border-0">
      <span className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <span
        className={`text-sm text-slate-200 text-right break-all ${mono ? 'font-mono' : ''}`}
      >
        {value}
      </span>
    </div>
  )
}

function ToolRunRow({ run }: { run: ToolRun }) {
  const [open, setOpen] = useState(false)
  const hasDetail = Boolean(run.command || run.summary)
  return (
    <>
      <tr
        className={`hover:bg-slate-800/40 ${hasDetail ? 'cursor-pointer' : ''}`}
        onClick={() => hasDetail && setOpen((o) => !o)}
      >
        <td className="td font-mono text-slate-200">
          {hasDetail && (
            <span className="mr-1 text-slate-500">{open ? '▾' : '▸'}</span>
          )}
          {run.tool_name}
        </td>
        <td className="td">
          <StatusBadge status={run.status} />
        </td>
        <td className="td text-slate-400">
          {run.exit_code != null ? run.exit_code : '—'}
          {run.timed_out && (
            <span className="ml-1 text-orange-400">(timeout)</span>
          )}
        </td>
        <td className="td text-xs text-slate-400">
          {run.summary || '—'}
        </td>
      </tr>
      {open && hasDetail && (
        <tr>
          <td className="td bg-slate-950/50" colSpan={4}>
            {run.command && (
              <div className="mb-2">
                <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">
                  Command
                </div>
                <ToolOutputViewer data={run.command} maxHeight="8rem" />
              </div>
            )}
            {run.summary && (
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">
                  Summary
                </div>
                <ToolOutputViewer data={run.summary} maxHeight="14rem" />
              </div>
            )}
            <div className="mt-2 text-xs text-slate-500">
              {fmtDate(run.started_at)} → {fmtDate(run.finished_at)}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function graphNodes(graph: ProtocolGraph | undefined) {
  return Array.isArray(graph?.nodes) ? graph.nodes : []
}

function graphSurfaces(graph: ProtocolGraph | undefined) {
  return Array.isArray(graph?.surfaces) ? graph.surfaces : []
}

function graphCandidates(graph: ProtocolGraph | undefined) {
  return Array.isArray(graph?.companion_scan_candidates)
    ? graph.companion_scan_candidates
    : []
}

function roleText(value: string | null | undefined) {
  return (value || 'unknown').replace(/_/g, ' ')
}

function ProtocolGraphPanel({ graph }: { graph?: ProtocolGraph }) {
  const nodes = graphNodes(graph)
  const surfaces = graphSurfaces(graph)
  const candidates = graphCandidates(graph)
  const components = nodes
    .filter((node) => node.role && node.role !== 'target')
    .slice(0, 12)

  if (nodes.length === 0 && surfaces.length === 0 && candidates.length === 0) {
    return null
  }

  return (
    <div className="card p-4 mb-8">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Protocol graph
        </h2>
        <span className="text-xs text-slate-500">
          {surfaces.length} surfaces · {candidates.length} companions
        </span>
      </div>

      {surfaces.length > 0 && (
        <div className="mb-4 flex flex-wrap gap-2">
          {surfaces.slice(0, 6).map((surface) => (
            <span
              key={surface.id}
              className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-xs text-amber-200"
              title={surface.next || surface.title || surface.id}
            >
              {surface.id.replace(/_/g, ' ')}
            </span>
          ))}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">
            Components
          </div>
          {components.length === 0 ? (
            <p className="text-sm text-slate-500">No companion components inferred.</p>
          ) : (
            <div className="space-y-2">
              {components.map((node) => (
                <div key={node.id} className="rounded-md border border-slate-800 bg-slate-950/50 px-3 py-2">
                  <div className="flex items-center justify-between gap-3">
                    <span className="truncate text-sm text-slate-200">{node.label || node.id}</span>
                    <span className="text-xs text-emerald-300">{roleText(node.role)}</span>
                  </div>
                  <div className="mt-1 font-mono text-xs text-slate-500">
                    {node.address ? shortAddr(node.address) : node.source || 'unresolved'}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div>
          <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">
            Companion scan candidates
          </div>
          {candidates.length === 0 ? (
            <p className="text-sm text-slate-500">No additional companion candidates.</p>
          ) : (
            <div className="space-y-2">
              {candidates.slice(0, 8).map((candidate, idx) => (
                <div key={`${candidate.role}-${candidate.label}-${idx}`} className="rounded-md border border-slate-800 bg-slate-950/50 px-3 py-2">
                  <div className="flex items-center justify-between gap-3">
                    <span className="truncate text-sm text-slate-200">{candidate.label || candidate.role || 'component'}</span>
                    <span className="text-xs text-slate-400">{roleText(candidate.role)}</span>
                  </div>
                  <div className="mt-1 font-mono text-xs text-slate-500">
                    {candidate.address ? shortAddr(candidate.address) : 'unresolved getter/source role'}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function ContractDetail() {
  const { id = '' } = useParams()
  const [target, setTarget] = useState<TargetWithDetails | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    api
      .getTarget(id)
      .then((t) => active && setTarget(t))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false))
    return () => {
      active = false
    }
  }, [id])

  if (loading) return <Spinner label="Loading contract…" />
  if (error) return <ErrorBox message={error} />
  if (!target) return <ErrorBox message="Target not found." />

  return (
    <div>
      <PageHeader
        title={target.contract_name || 'Contract'}
        subtitle={
          <span className="font-mono text-emerald-400 break-all">
            {target.address}
          </span>
        }
        actions={<StatusBadge status={target.status} />}
      />

      <div className="card p-4 mb-6">
        <ProgressTimeline current={statusToStage(target.status)} />
      </div>

      {target.error && (
        <div className="mb-4">
          <ErrorBox message={target.error} />
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2 mb-8">
        <div className="card p-4">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">
            Overview
          </h2>
          <InfoRow label="Chain" value={target.chain} mono />
          <InfoRow label="Label" value={target.label || '—'} />
          <InfoRow
            label="Source verified"
            value={
              target.source_verified ? (
                <span className="text-emerald-400">yes</span>
              ) : (
                <span className="text-red-400">no</span>
              )
            }
          />
          <InfoRow label="Owner" value={target.owner || '—'} mono />
          <InfoRow
            label="Balance"
            value={
              target.balance_eth != null
                ? `${target.balance_eth} ETH`
                : '—'
            }
            mono
          />
          <InfoRow label="Updated" value={fmtDate(target.updated_at)} />
        </div>

        <div className="card p-4">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">
            Proxy
          </h2>
          {target.is_proxy ? (
            <>
              <InfoRow label="Is proxy" value={<span className="text-amber-400">yes</span>} />
              <InfoRow label="Type" value={target.proxy_type || '—'} />
              <InfoRow
                label="Implementation"
                value={target.implementation_address || '—'}
                mono
              />
              <InfoRow label="Admin" value={target.proxy_admin || '—'} mono />
            </>
          ) : (
            <p className="text-sm text-slate-500 py-2">
              Not detected as a proxy.
            </p>
          )}
        </div>
      </div>

      <ProtocolGraphPanel graph={target.protocol_graph} />

      {/* Tool runs */}
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
        Tool runs ({target.tool_runs.length})
      </h2>
      <div className="card mb-8 overflow-hidden">
        <table className="w-full">
          <thead className="border-b border-slate-800 bg-slate-900/80">
            <tr>
              <th className="th">Tool</th>
              <th className="th">Status</th>
              <th className="th">Exit</th>
              <th className="th">Summary</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {target.tool_runs.map((run) => (
              <ToolRunRow key={run.id} run={run} />
            ))}
            {target.tool_runs.length === 0 && (
              <tr>
                <td className="td text-slate-500" colSpan={4}>
                  No tool runs recorded.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Findings */}
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
        Findings ({target.findings.length})
      </h2>
      {target.findings.length === 0 ? (
        <EmptyState>No findings for this contract.</EmptyState>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          {target.findings.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  )
}
