import { useEffect, useState, useCallback } from 'react'
import { api, type ToolHealth as ToolHealthData } from '../api'
import { PageHeader, Spinner, ErrorBox, fmtDate } from '../components/ui'

export default function ToolHealth() {
  const [data, setData] = useState<ToolHealthData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const d = await api.getToolHealth()
      setData(d)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  return (
    <div>
      <PageHeader
        title="Tool Health"
        subtitle={
          data ? `Last checked ${fmtDate(data.checked_at)}` : 'Analysis toolchain status'
        }
        actions={
          <button className="btn-secondary" onClick={load} disabled={loading}>
            {loading ? 'Checking…' : 'Re-check'}
          </button>
        }
      />

      {loading && !data && <Spinner label="Checking tools…" />}
      {error && <ErrorBox message={error} />}

      {data && (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead className="border-b border-slate-800 bg-slate-900/80">
              <tr>
                <th className="th">Tool</th>
                <th className="th">Installed</th>
                <th className="th">Version</th>
                <th className="th">Path</th>
                <th className="th">Warning</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {data.tools.map((tool) => (
                <tr key={tool.name} className="hover:bg-slate-800/40">
                  <td className="td font-medium text-slate-100">{tool.name}</td>
                  <td className="td">
                    {tool.installed ? (
                      <span className="inline-flex items-center gap-1.5 text-emerald-400">
                        <span className="h-2 w-2 rounded-full bg-emerald-400" />
                        Installed
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-red-400">
                        <span className="h-2 w-2 rounded-full bg-red-400" />
                        Missing
                      </span>
                    )}
                  </td>
                  <td className="td font-mono text-xs text-slate-400">
                    {tool.version || '—'}
                  </td>
                  <td className="td font-mono text-xs text-slate-500 break-all">
                    {tool.path || '—'}
                  </td>
                  <td className="td text-xs text-amber-400">
                    {tool.warning || '—'}
                  </td>
                </tr>
              ))}
              {data.tools.length === 0 && (
                <tr>
                  <td className="td text-slate-500" colSpan={5}>
                    No tools reported.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
