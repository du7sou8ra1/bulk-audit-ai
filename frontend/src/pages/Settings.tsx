import { useEffect, useState, type ReactNode } from 'react'
import { api, type Settings as SettingsData } from '../api'
import { PageHeader, Spinner, ErrorBox } from '../components/ui'

function Row({
  label,
  value,
  configured,
  mono,
}: {
  label: string
  value: ReactNode
  configured?: boolean
  mono?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5 border-b border-slate-800 last:border-0">
      <span className="text-sm text-slate-400">{label}</span>
      <span className="flex items-center gap-2">
        <span
          className={`text-sm text-slate-200 break-all text-right ${mono ? 'font-mono' : ''}`}
        >
          {value || '—'}
        </span>
        {configured !== undefined &&
          (configured ? (
            <span className="shrink-0 rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] uppercase text-emerald-400">
              set
            </span>
          ) : (
            <span className="shrink-0 rounded border border-slate-600/40 bg-slate-700/20 px-1.5 py-0.5 text-[10px] uppercase text-slate-500">
              unset
            </span>
          ))}
      </span>
    </div>
  )
}

function ToggleRow({ label, on }: { label: string; on: boolean }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-slate-800 last:border-0">
      <span className="text-sm text-slate-300">{label}</span>
      <span
        className={`rounded border px-2 py-0.5 text-xs font-medium ${
          on
            ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
            : 'border-slate-600/40 bg-slate-700/20 text-slate-500'
        }`}
      >
        {on ? 'enabled' : 'disabled'}
      </span>
    </div>
  )
}

export default function Settings() {
  const [data, setData] = useState<SettingsData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    api
      .getSettings()
      .then((d) => active && setData(d))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false))
    return () => {
      active = false
    }
  }, [])

  return (
    <div>
      <PageHeader title="Settings" subtitle="Read-only runtime configuration" />

      <div className="card border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-300 mb-6">
        Edit <code className="font-mono">.env</code> and restart to change.
        Secrets are masked and never stored in the database.
      </div>

      {loading && <Spinner />}
      {error && <ErrorBox message={error} />}

      {data && (
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="card p-4">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">
              Network
            </h2>
            <Row label="Chain" value={data.chain} mono />
            <Row
              label="RPC URL"
              value={data.rpc_url}
              configured={data.rpc_url_configured}
              mono
            />
            <Row
              label="Etherscan API key"
              value={data.etherscan_api_key}
              configured={data.etherscan_configured}
              mono
            />
          </div>

          <div className="card p-4">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">
              DeepSeek (AI)
            </h2>
            <Row
              label="API key"
              value={data.deepseek_api_key}
              configured={data.deepseek_configured}
              mono
            />
            <Row label="Base URL" value={data.deepseek_base_url} mono />
            <Row label="Model" value={data.deepseek_model} mono />
          </div>

          <div className="card p-4">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">
              Tool toggles
            </h2>
            <ToggleRow label="Slither" on={data.toggles.slither} />
            <ToggleRow label="Mythril" on={data.toggles.mythril} />
            <ToggleRow label="Semgrep" on={data.toggles.semgrep} />
            <ToggleRow label="Foundry" on={data.toggles.foundry} />
            <ToggleRow label="Fuzzing" on={data.toggles.fuzzing} />
            <ToggleRow label="DeepSeek" on={data.toggles.deepseek} />
          </div>

          <div className="card p-4">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400 mb-2">
              Limits
            </h2>
            {Object.keys(data.limits || {}).length === 0 ? (
              <p className="text-sm text-slate-500 py-2">No limits reported.</p>
            ) : (
              Object.entries(data.limits).map(([k, v]) => (
                <Row key={k} label={k} value={String(v)} mono />
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
