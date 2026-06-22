import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, type ScanProfile, type Toggles } from '../api'
import { PageHeader, ErrorBox } from '../components/ui'
import AddressInputBox, { parseAddresses } from '../components/AddressInputBox'

const CHAINS = [
  'ethereum',
  'arbitrum',
  'optimism',
  'base',
  'polygon',
  'bsc',
  'avalanche',
]

// Fallback only — the live list is fetched from /api/scan-profiles so the dropdown
// can never drift from the backend registry.
const FALLBACK_PROFILES: ScanProfile[] = [
  // single-mode build: 'deep' is the only profile (runs every detector).
  { value: 'deep', label: 'Deep' },
]

const TOOL_DEFS: { key: keyof Toggles; label: string; hint: string }[] = [
  { key: 'slither', label: 'Slither', hint: 'Static analysis' },
  { key: 'mythril', label: 'Mythril', hint: 'Symbolic execution' },
  { key: 'semgrep', label: 'Semgrep', hint: 'Pattern rules' },
  { key: 'foundry', label: 'Foundry simulations', hint: 'On-chain forks' },
  { key: 'deepseek', label: 'DeepSeek AI review', hint: 'LLM triage' },
]

export default function NewScan() {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [chain, setChain] = useState('ethereum')
  const [profile, setProfile] = useState('deep')
  const [profiles, setProfiles] = useState<ScanProfile[]>(FALLBACK_PROFILES)

  useEffect(() => {
    let active = true
    api
      .getScanProfiles()
      .then((r) => {
        if (active && r.profiles?.length) setProfiles(r.profiles)
      })
      .catch(() => {
        /* keep the fallback list */
      })
    return () => {
      active = false
    }
  }, [])
  const [blob, setBlob] = useState('')
  const [toggles, setToggles] = useState<Record<keyof Toggles, boolean>>({
    slither: true,
    mythril: true,
    semgrep: true,
    foundry: false,
    deepseek: true,
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const targets = parseAddresses(blob)
  const canSubmit = targets.length > 0 && !submitting

  function toggle(key: keyof Toggles) {
    setToggles((t) => ({ ...t, [key]: !t[key] }))
  }

  async function submit() {
    if (!canSubmit) return
    setSubmitting(true)
    setError(null)
    try {
      const scan = await api.createScan({
        name: name.trim() || `Scan ${new Date().toLocaleString()}`,
        chain,
        scan_profile: profile,
        addresses_blob: blob,
        targets,
        toggles: {
          slither: toggles.slither,
          mythril: toggles.mythril,
          semgrep: toggles.semgrep,
          foundry: toggles.foundry,
          deepseek: toggles.deepseek,
        },
      })
      navigate(`/scans/${scan.id}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setSubmitting(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="New Scan"
        subtitle="Paste contract addresses to triage in bulk"
      />

      {error && (
        <div className="mb-4">
          <ErrorBox message={error} />
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          <div>
            <label className="label">Scan name</label>
            <input
              className="input"
              placeholder="e.g. Protocol X governance sweep"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div>
            <label className="label">Addresses</label>
            <AddressInputBox value={blob} onChange={setBlob} />
          </div>
        </div>

        <div className="space-y-4">
          <div>
            <label className="label">Chain</label>
            <select
              className="input"
              value={chain}
              onChange={(e) => setChain(e.target.value)}
            >
              {CHAINS.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="label">Scan profile</label>
            <select
              className="input"
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
            >
              {profiles.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="label">Tools</label>
            <div className="card divide-y divide-slate-800">
              {TOOL_DEFS.map((tool) => (
                <label
                  key={tool.key}
                  className="flex items-center gap-3 px-3 py-2.5 cursor-pointer hover:bg-slate-800/40"
                >
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-emerald-500 focus:ring-emerald-600/50"
                    checked={toggles[tool.key]}
                    onChange={() => toggle(tool.key)}
                  />
                  <span className="flex-1">
                    <span className="text-sm text-slate-200">{tool.label}</span>
                    <span className="block text-xs text-slate-500">
                      {tool.hint}
                    </span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          <button
            className="btn-primary w-full"
            disabled={!canSubmit}
            onClick={submit}
          >
            {submitting
              ? 'Starting…'
              : `Start scan (${targets.length} target${targets.length === 1 ? '' : 's'})`}
          </button>
          {targets.length === 0 && (
            <p className="text-xs text-slate-500 text-center">
              Add at least one valid 0x address to start.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
