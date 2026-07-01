// Typed API client for the BulkAuditAI backend.
// Base path is same-origin; Vite proxies /api and /ws to http://localhost:8000.

// ----------------------------- Types -----------------------------

export type ScanStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'

export type ToolRunStatus =
  | 'pending'
  | 'running'
  | 'ok'
  | 'failed'
  | 'timeout'
  | 'skipped'

export type Classification =
  | 'CONFIRMED_CRITICAL'
  | 'LIKELY_CRITICAL_NEEDS_POC'
  | 'NEEDS_MORE_INVESTIGATION'
  | 'LOW_OR_INFO'
  | 'FALSE_POSITIVE'

export interface Toggles {
  slither: boolean | null
  mythril: boolean | null
  semgrep: boolean | null
  foundry: boolean | null
  fuzzing: boolean | null
  bytecode_intel: boolean | null
  bytecode_probes: boolean | null
  deepseek: boolean | null
  invariant_reasoner: boolean | null
  refutation: boolean | null
  flashloan_sim: boolean | null
  value_context: boolean | null
  sanity_liveness: boolean | null
  binding_hard_gate: boolean | null
  pattern_priors: boolean | null
}

export interface Scan {
  id: string
  name: string
  created_at: string
  started_at?: string | null
  finished_at?: string | null
  status: ScanStatus
  chain: string
  scan_profile: string
  toggles: Toggles
  total_targets: number
  completed_targets: number
  critical_count: number
  needs_investigation_count: number
  low_info_count: number
  false_positive_count: number
  error?: string | null
}

export interface Target {
  id: string
  scan_id: string
  address: string
  chain: string
  label: string
  status: string
  source_verified: boolean
  contract_name?: string | null
  is_proxy: boolean
  proxy_type?: string | null
  implementation_address?: string | null
  proxy_admin?: string | null
  owner?: string | null
  balance_eth?: number | null
  error?: string | null
  updated_at: string
}

export interface ToolRun {
  id: string
  tool_name: string
  status: ToolRunStatus
  started_at?: string | null
  finished_at?: string | null
  command?: string | null
  exit_code?: number | null
  timed_out: boolean
  summary?: string | null
}

export interface Finding {
  id: string
  target_id: string
  detector: string
  title: string
  severity_candidate: string
  confidence_before_ai: string
  impact_score: number
  confidence_score: number
  status: string
  classification: Classification
  description: string
  evidence_json: Record<string, unknown>
  next_tests_json: unknown[]
  created_at: string
}

export interface AIReview {
  id: string
  model: string
  classification?: Classification | null
  rationale?: string | null
  recommended_next_steps: unknown[]
  request_json: Record<string, unknown>
  response_json: Record<string, unknown>
  created_at: string
}

export interface DashboardData {
  total_scans: number
  running_scans: number
  completed_scans: number
  critical_candidates: number
  needs_investigation: number
  low_info: number
  false_positives: number
  recent_scans: Scan[]
}

export interface ToolHealthEntry {
  name: string
  installed: boolean
  version: string | null
  path: string | null
  warning: string | null
}


export interface ProtocolGraphNode {
  id: string
  label?: string | null
  kind?: string | null
  role?: string | null
  address?: string | null
  source?: string | null
  confidence?: number | null
}

export interface ProtocolGraphSurface {
  id: string
  title?: string | null
  severity?: string | null
  confidence?: number | null
  target_address?: string | null
  target_label?: string | null
  next?: string | null
}

export interface ProtocolGraphCandidate {
  role?: string | null
  label?: string | null
  address?: string | null
  source?: string | null
  confidence?: number | null
  unresolved?: boolean | null
  already_in_scan?: boolean | null
}

export interface ProtocolGraphGroup {
  id?: string | null
  title?: string | null
  severity?: string | null
  members?: ProtocolGraphCandidate[]
}

export interface ProtocolGraph {
  schema?: string
  summary?: Record<string, unknown>
  nodes?: ProtocolGraphNode[]
  edges?: Record<string, unknown>[]
  surfaces?: ProtocolGraphSurface[]
  groups?: ProtocolGraphGroup[]
  companion_scan_candidates?: ProtocolGraphCandidate[]
}

export interface ToolHealth {
  checked_at: string
  tools: ToolHealthEntry[]
}

export interface Settings {
  rpc_url: string
  rpc_url_configured: boolean
  chain: string
  etherscan_api_key: string
  etherscan_configured: boolean
  deepseek_api_key: string
  deepseek_configured: boolean
  deepseek_base_url: string
  deepseek_model: string
  toggles: {
    slither: boolean
    mythril: boolean
    semgrep: boolean
    foundry: boolean
    fuzzing: boolean
    bytecode_intel: boolean
    bytecode_probes: boolean
    deepseek: boolean
    invariant_reasoner: boolean
    refutation: boolean
    sourcify: boolean
    flashloan_sim: boolean
    value_context: boolean
    sanity_liveness: boolean
    refuter_precision_rules: boolean
    binding_hard_gate: boolean
    critical_value_gate: boolean
    pattern_priors: boolean
    companion_expansion: boolean
  }
  limits: Record<string, unknown>
}

export interface TargetSpec {
  address: string
  label: string
}

export interface NewScanPayload {
  name: string
  chain: string
  scan_profile: string
  addresses_blob: string
  targets: TargetSpec[]
  toggles: Toggles
  companion_expansion: boolean
  companion_expansion_max: number
}

export type ScanWithTargets = Scan & { targets: Target[]; protocol_graph?: ProtocolGraph }
export type TargetWithDetails = Target & {
  tool_runs: ToolRun[]
  findings: Finding[]
  protocol_graph?: ProtocolGraph
}
export type FindingWithDetails = Finding & {
  ai_review: AIReview | null
  target_address: string
}

// --------------------- Monitoring ("before-drain") ----------------

export interface WatchTarget {
  id: number
  address: string
  chain: string
  label: string
  enabled: boolean
  scan_profile: string
  interval_seconds: number | null
  github_url: string | null
  impl_address: string | null
  codehash: string | null
  admin: string | null
  owner: string | null
  last_checked_at: string | null
  last_change_at: string | null
  last_scan_id: number | null
  created_at: string
}

export interface WatchEventRow {
  kind: string
  detail: Record<string, unknown>
  scan_id: number | null
  created_at: string
}

export type WatchTargetWithEvents = WatchTarget & { events: WatchEventRow[] }

export interface DeployerWatch {
  id: number
  deployer_address: string
  chain: string
  label: string
  enabled: boolean
  scan_profile: string
  interval_seconds: number | null
  last_block_checked: number
  deployed_count: number
  last_checked_at: string | null
  created_at: string
}

export interface MonitorStatus {
  running: boolean
  interval_seconds: number
  alerts_configured: boolean
  enable_monitor_default: boolean
}

export interface Suppression {
  id: number
  fingerprint: string
  address: string | null
  detector: string
  title: string
  reason: string
  created_at: string
}

export interface AddWatchPayload {
  addresses_blob: string
  chain: string
  scan_profile: string
}

// --------------------------- HTTP core ---------------------------

class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(path, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  })

  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body && typeof body === 'object' && 'detail' in body) {
        detail = String((body as { detail: unknown }).detail)
      }
    } catch {
      // ignore non-JSON error bodies
    }
    throw new ApiError(detail, res.status)
  }

  if (res.status === 204) {
    return undefined as unknown as T
  }
  return (await res.json()) as T
}

// --------------------------- Endpoints ---------------------------

export interface ScanProfile {
  value: string
  label: string
}

export const api = {
  getDashboard: () => request<DashboardData>('/api/dashboard'),

  getScanProfiles: () =>
    request<{ profiles: ScanProfile[] }>('/api/scan-profiles'),

  getToolHealth: () => request<ToolHealth>('/api/health/tools'),

  getSettings: () => request<Settings>('/api/settings'),

  listScans: () => request<Scan[]>('/api/scans'),

  createScan: (payload: NewScanPayload) =>
    request<Scan>('/api/scans', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getScan: (id: string) => request<ScanWithTargets>(`/api/scans/${id}`),

  cancelScan: (id: string) =>
    request<Scan>(`/api/scans/${id}/cancel`, { method: 'POST' }),

  rescanScan: (id: string) =>
    request<Scan>(`/api/scans/${id}/rescan`, { method: 'POST' }),

  getScanFindings: (id: string) =>
    request<Finding[]>(`/api/scans/${id}/findings`),

  getTarget: (id: string) =>
    request<TargetWithDetails>(`/api/targets/${id}`),

  getFinding: (id: string) =>
    request<FindingWithDetails>(`/api/findings/${id}`),

  setFindingStatus: (id: string, status: string) =>
    request<Finding>(`/api/findings/${id}/status`, {
      method: 'POST',
      body: JSON.stringify({ status }),
    }),

  exportScanUrl: (id: string, format: 'json' | 'csv' | 'md' | 'zip') =>
    `/api/scans/${id}/export?format=${format}`,

  exportFindingMarkdownUrl: (id: string) =>
    `/api/findings/${id}/export?format=md`,

  // --- Monitoring ---
  listWatch: () => request<WatchTarget[]>('/api/watch'),
  getWatch: (id: number) => request<WatchTargetWithEvents>(`/api/watch/${id}`),
  addWatch: (body: AddWatchPayload) =>
    request<{ added: string[]; skipped_existing: string[] }>('/api/watch', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  deleteWatch: (id: number) =>
    request<{ deleted: number }>(`/api/watch/${id}`, { method: 'DELETE' }),
  checkWatch: (id: number) =>
    request<Record<string, unknown>>(`/api/watch/${id}/check`, { method: 'POST' }),

  listDeployers: () => request<DeployerWatch[]>('/api/deployers'),
  addDeployer: (body: AddWatchPayload) =>
    request<{ added: string[]; skipped_existing: string[] }>('/api/deployers', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  deleteDeployer: (id: number) =>
    request<{ deleted: number }>(`/api/deployers/${id}`, { method: 'DELETE' }),
  checkDeployer: (id: number) =>
    request<Record<string, unknown>>(`/api/deployers/${id}/check`, { method: 'POST' }),

  monitorStatus: () => request<MonitorStatus>('/api/monitor/status'),
  monitorStart: () => request<MonitorStatus>('/api/monitor/start', { method: 'POST' }),
  monitorStop: () => request<MonitorStatus>('/api/monitor/stop', { method: 'POST' }),

  listSuppressions: () => request<Suppression[]>('/api/suppressions'),
  deleteSuppression: (id: number) =>
    request<{ deleted: number }>(`/api/suppressions/${id}`, { method: 'DELETE' }),
}

// --------------------------- WebSocket ---------------------------

export interface ScanEvent {
  type: 'target_update' | 'scan_update' | 'log' | 'tool_update' | string
  [key: string]: unknown
}

export function openScanSocket(
  scanId: string,
  onMessage: (event: ScanEvent) => void,
  onError: () => void,
): WebSocket | null {
  try {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(
      `${proto}://${window.location.host}/ws/scans/${scanId}`,
    )
    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data) as ScanEvent
        onMessage(data)
      } catch {
        // ignore malformed frames
      }
    }
    ws.onerror = () => onError()
    return ws
  } catch {
    onError()
    return null
  }
}

export { ApiError }
