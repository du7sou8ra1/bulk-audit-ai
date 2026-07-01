import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, type ScanProfile, type Toggles, type ToolHealthEntry } from '../api'
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
  { value: 'deep', label: 'Deep' },
  { value: 'ultra-deep', label: 'Ultra-deep (2026 exploit classes)' },
  { value: 'ultra-deep-v2', label: 'Ultra deep v2' },
]

const TOOL_DEFS: { key: keyof Toggles; label: string; hint: string }[] = [
  { key: 'slither', label: 'Slither', hint: 'Static analysis' },
  { key: 'mythril', label: 'Mythril', hint: 'Symbolic execution' },
  { key: 'semgrep', label: 'Semgrep', hint: 'Pattern rules' },
  { key: 'bytecode_intel', label: 'Bytecode intel', hint: 'Selectors + opcode risk signals' },
  { key: 'bytecode_probes', label: 'Bytecode probes', hint: 'Selector-specific fork probe plan' },
  { key: 'foundry', label: 'Foundry simulations', hint: 'On-chain forks' },
  { key: 'fuzzing', label: 'Fuzzing', hint: 'Foundry + Echidna + Medusa handoff' },
  { key: 'flashloan_sim', label: 'Flashloan sims', hint: 'Oracle/donation fork checks' },
  { key: 'invariant_reasoner', label: 'Invariant reasoner', hint: 'Cross-function hypotheses' },
  { key: 'refutation', label: 'Refuter', hint: 'Adversarial finding review' },
  { key: 'value_context', label: 'Value context', hint: 'Read-only value/dependency evidence' },
  { key: 'sanity_liveness', label: 'Sanity liveness', hint: 'Initializer/proxy liveness reads' },
  { key: 'binding_hard_gate', label: 'Binding hard gate', hint: 'Caller-bound false-positive guard' },
  { key: 'pattern_priors', label: 'Pattern priors', hint: 'Use prior refutations as context' },
  { key: 'deepseek', label: 'DeepSeek AI review', hint: 'LLM triage' },
]

const FUZZER_TOOLS = ['forge', 'echidna', 'medusa'] as const

export default function NewScan() {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [chain, setChain] = useState('ethereum')
  const [profile, setProfile] = useState('deep')
  const [profiles, setProfiles] = useState<ScanProfile[]>(FALLBACK_PROFILES)
  const [toolHealth, setToolHealth] = useState<ToolHealthEntry[]>([])

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

  useEffect(() => {
    let active = true
    api
      .getToolHealth()
      .then((r) => {
        if (active) setToolHealth(r.tools || [])
      })
      .catch(() => {
        /* tool health is optional for the scan form */
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
    fuzzing: false,
    bytecode_intel: true,
    bytecode_probes: true,
    deepseek: true,
    invariant_reasoner: true,
    refutation: true,
    flashloan_sim: true,
    value_context: true,
    sanity_liveness: true,
    binding_hard_gate: true,
    pattern_priors: true,
  })
  const [companionExpansion, setCompanionExpansion] = useState(false)
  const [companionExpansionMax, setCompanionExpansionMax] = useState(8)

  useEffect(() => {
    if (profile === 'ultra-deep-v2') {
      setToggles((t) => (t.fuzzing ? t : { ...t, fuzzing: true }))
      setCompanionExpansion(true)
    }
  }, [profile])

  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const targets = parseAddresses(blob)
  const canSubmit = targets.length > 0 && !submitting

  function toggle(key: keyof Toggles) {
    setToggles((t) => ({ ...t, [key]: !t[key] }))
  }

  function healthFor(name: string) {
    return toolHealth.find((tool) => tool.name.toLowerCase() === name)
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
        toggles,
        companion_expansion: companionExpansion,
        companion_expansion_max: companionExpansionMax,
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
            <label className="label">Protocol expansion</label>
            <div className="card p-3 space-y-3">
              <label className="flex cursor-pointer items-start gap-3">
                <input
                  type="checkbox"
                  className="mt-1 h-4 w-4 rounded border-slate-600 bg-slate-900 text-emerald-500 focus:ring-emerald-600/50"
                  checked={companionExpansion}
                  onChange={() => setCompanionExpansion((v) => !v)}
                />
                <span className="flex-1">
                  <span className="text-sm text-slate-200">Auto-scan companions</span>
                  <span className="block text-xs text-slate-500">
                    Resolved oracle, market, vault, AMM, bridge, verifier, and strategy contracts.
                  </span>
                </span>
              </label>
              <div className="grid grid-cols-[1fr_104px] items-center gap-3">
                <span className="text-xs uppercase tracking-wide text-slate-500">Max additions</span>
                <select
                  className="input h-9 py-1 text-sm"
                  value={companionExpansionMax}
                  disabled={!companionExpansion}
                  onChange={(e) => setCompanionExpansionMax(Number(e.target.value))}
                >
                  {[3, 6, 8, 12, 16, 25].map((n) => (
                    <option key={n} value={n}>{n}</option>
                  ))}
                </select>
              </div>
            </div>
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
                    {tool.key === 'fuzzing' && (
                      <span className="mt-2 flex flex-wrap gap-1.5">
                        {FUZZER_TOOLS.map((name) => {
                          const health = healthFor(name)
                          const installed = health?.installed
                          return (
                            <span
                              key={name}
                              className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase ${
                                installed
                                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                  : health
                                    ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                    : 'border-slate-700 bg-slate-900/60 text-slate-500'
                              }`}
                              title={health?.version || health?.warning || 'checking'}
                            >
                              <span
                                className={`h-1.5 w-1.5 rounded-full ${
                                  installed ? 'bg-emerald-400' : health ? 'bg-amber-400' : 'bg-slate-600'
                                }`}
                              />
                              {name}
                            </span>
                          )
                        })}
                      </span>
                    )}
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
