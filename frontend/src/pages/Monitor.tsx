import { useCallback, useEffect, useState } from 'react'
import {
  api,
  type DeployerWatch,
  type MonitorStatus,
  type Suppression,
  type WatchTarget,
} from '../api'
import { PageHeader, Spinner, ErrorBox, EmptyState, shortAddr, fmtDate } from '../components/ui'

const CHAINS = ['ethereum', 'base', 'arbitrum', 'optimism', 'polygon', 'bsc',
  'scroll', 'linea', 'avalanche', 'blast']
const PROFILES = ['defi-deep', 'deep', 'standard', 'oracle-focused',
  'bridge-focused', 'zk-focused', 'governance-focused']

const inputCls =
  'w-full rounded-md bg-slate-900 border border-slate-700 px-3 py-2 text-sm text-slate-200 focus:border-emerald-500/60 focus:outline-none'
const btnPrimary =
  'rounded-md bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-sm font-medium text-white disabled:opacity-50'

export default function Monitor() {
  const [status, setStatus] = useState<MonitorStatus | null>(null)
  const [watches, setWatches] = useState<WatchTarget[]>([])
  const [deployers, setDeployers] = useState<DeployerWatch[]>([])
  const [suppressions, setSuppressions] = useState<Suppression[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const [wBlob, setWBlob] = useState('')
  const [wChain, setWChain] = useState('ethereum')
  const [wProfile, setWProfile] = useState('defi-deep')
  const [dBlob, setDBlob] = useState('')
  const [dChain, setDChain] = useState('ethereum')
  const [dProfile, setDProfile] = useState('defi-deep')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [st, w, d, s] = await Promise.all([
        api.monitorStatus(), api.listWatch(), api.listDeployers(), api.listSuppressions(),
      ])
      setStatus(st); setWatches(w); setDeployers(d); setSuppressions(s)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const act = useCallback(async (fn: () => Promise<unknown>, note: string) => {
    setBusy(true); setMsg(null)
    try { await fn(); setMsg(note); await load() }
    catch (e) { setError(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }, [load])

  const toggleMonitor = () =>
    act(() => (status?.running ? api.monitorStop() : api.monitorStart()),
      status?.running ? 'Monitor stopped' : 'Monitor started')

  return (
    <div className="space-y-8">
      <PageHeader
        title="Monitor"
        subtitle="Before-drain watch: contract upgrades & new deployments → auto-rescan + alert"
        actions={
          <button className="btn-secondary" onClick={() => void load()} disabled={loading}>
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        }
      />

      {error && <ErrorBox message={error} />}
      {msg && <div className="card border-emerald-500/30 bg-emerald-500/5 p-3 text-sm text-emerald-300">{msg}</div>}
      {loading && !status && <Spinner label="Loading monitor…" />}

      {status && (
        <div className="card p-4 flex flex-wrap items-center gap-4">
          <span className="inline-flex items-center gap-2 text-sm">
            <span className={`h-2.5 w-2.5 rounded-full ${status.running ? 'bg-emerald-400' : 'bg-slate-500'}`} />
            <span className="text-slate-200 font-medium">
              {status.running ? 'Monitor running' : 'Monitor stopped'}
            </span>
            <span className="text-slate-500">· every {status.interval_seconds}s</span>
          </span>
          <span className={`text-xs ${status.alerts_configured ? 'text-emerald-400' : 'text-amber-400'}`}>
            {status.alerts_configured ? 'Webhook alerts configured' : 'No ALERT_WEBHOOK_URL — alerts disabled'}
          </span>
          <button className={btnPrimary} onClick={toggleMonitor} disabled={busy}>
            {status.running ? 'Stop monitor' : 'Start monitor'}
          </button>
        </div>
      )}

      {/* Watched contracts */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-slate-100">Watched contracts</h2>
        <div className="card p-4 grid gap-3 sm:grid-cols-[1fr_auto_auto_auto]">
          <textarea className={inputCls} rows={2} placeholder="0x… one per line"
            value={wBlob} onChange={(e) => setWBlob(e.target.value)} />
          <select className={inputCls} value={wChain} onChange={(e) => setWChain(e.target.value)}>
            {CHAINS.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <select className={inputCls} value={wProfile} onChange={(e) => setWProfile(e.target.value)}>
            {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <button className={btnPrimary} disabled={busy || !wBlob.trim()}
            onClick={() => act(async () => { await api.addWatch({ addresses_blob: wBlob, chain: wChain, scan_profile: wProfile }); setWBlob('') }, 'Contracts added')}>
            Watch
          </button>
        </div>
        {watches.length === 0 ? (
          <EmptyState>No watched contracts yet. They are auto-watched for implementation upgrades.</EmptyState>
        ) : (
          <div className="card overflow-hidden">
            <table className="w-full">
              <thead className="border-b border-slate-800 bg-slate-900/80">
                <tr>
                  <th className="th">Address</th><th className="th">Chain</th>
                  <th className="th">Implementation</th><th className="th">Last checked</th>
                  <th className="th">Last change</th><th className="th"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {watches.map((w) => (
                  <tr key={w.id} className="hover:bg-slate-800/40">
                    <td className="td font-mono text-xs text-slate-200">{shortAddr(w.address)}</td>
                    <td className="td text-xs text-slate-400">{w.chain}</td>
                    <td className="td font-mono text-xs text-slate-400">{shortAddr(w.impl_address)}</td>
                    <td className="td text-xs text-slate-400">{fmtDate(w.last_checked_at)}</td>
                    <td className={`td text-xs ${w.last_change_at ? 'text-amber-400' : 'text-slate-500'}`}>{fmtDate(w.last_change_at)}</td>
                    <td className="td text-right whitespace-nowrap">
                      <button className="text-xs text-emerald-400 hover:underline mr-3" disabled={busy}
                        onClick={() => act(() => api.checkWatch(w.id), 'Checked')}>Check now</button>
                      <button className="text-xs text-red-400 hover:underline" disabled={busy}
                        onClick={() => act(() => api.deleteWatch(w.id), 'Removed')}>Remove</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Watched deployers */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-slate-100">Watched deployers</h2>
        <p className="text-sm text-slate-500">Auto-onboard + scan every new contract these addresses ship.</p>
        <div className="card p-4 grid gap-3 sm:grid-cols-[1fr_auto_auto_auto]">
          <textarea className={inputCls} rows={2} placeholder="deployer 0x… one per line"
            value={dBlob} onChange={(e) => setDBlob(e.target.value)} />
          <select className={inputCls} value={dChain} onChange={(e) => setDChain(e.target.value)}>
            {CHAINS.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <select className={inputCls} value={dProfile} onChange={(e) => setDProfile(e.target.value)}>
            {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <button className={btnPrimary} disabled={busy || !dBlob.trim()}
            onClick={() => act(async () => { await api.addDeployer({ addresses_blob: dBlob, chain: dChain, scan_profile: dProfile }); setDBlob('') }, 'Deployers added')}>
            Watch
          </button>
        </div>
        {deployers.length === 0 ? (
          <EmptyState>No watched deployers. Add a team's deployer EOA/factory to catch fresh launches.</EmptyState>
        ) : (
          <div className="card overflow-hidden">
            <table className="w-full">
              <thead className="border-b border-slate-800 bg-slate-900/80">
                <tr>
                  <th className="th">Deployer</th><th className="th">Chain</th>
                  <th className="th">Deployed</th><th className="th">Last block</th>
                  <th className="th">Last checked</th><th className="th"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {deployers.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-800/40">
                    <td className="td font-mono text-xs text-slate-200">{shortAddr(d.deployer_address)}</td>
                    <td className="td text-xs text-slate-400">{d.chain}</td>
                    <td className="td text-xs text-slate-300">{d.deployed_count}</td>
                    <td className="td text-xs text-slate-500">{d.last_block_checked || '—'}</td>
                    <td className="td text-xs text-slate-400">{fmtDate(d.last_checked_at)}</td>
                    <td className="td text-right whitespace-nowrap">
                      <button className="text-xs text-emerald-400 hover:underline mr-3" disabled={busy}
                        onClick={() => act(() => api.checkDeployer(d.id), 'Checked deployer')}>Check now</button>
                      <button className="text-xs text-red-400 hover:underline" disabled={busy}
                        onClick={() => act(() => api.deleteDeployer(d.id), 'Removed')}>Remove</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Suppressions */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-slate-100">Suppressed findings (FP-learning)</h2>
        {suppressions.length === 0 ? (
          <EmptyState>No suppressions. Mark a finding false-positive to auto-suppress its fingerprint.</EmptyState>
        ) : (
          <div className="card overflow-hidden">
            <table className="w-full">
              <thead className="border-b border-slate-800 bg-slate-900/80">
                <tr>
                  <th className="th">Detector</th><th className="th">Title</th>
                  <th className="th">Scope</th><th className="th">Reason</th><th className="th"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {suppressions.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-800/40">
                    <td className="td text-xs text-slate-300">{s.detector || '—'}</td>
                    <td className="td text-xs text-slate-400">{s.title || '—'}</td>
                    <td className="td text-xs text-slate-400">{s.address ? shortAddr(s.address) : 'global'}</td>
                    <td className="td text-xs text-slate-500">{s.reason}</td>
                    <td className="td text-right">
                      <button className="text-xs text-red-400 hover:underline" disabled={busy}
                        onClick={() => act(() => api.deleteSuppression(s.id), 'Suppression removed')}>Unsuppress</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
