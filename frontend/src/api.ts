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
  deepseek: boolean | null
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
    deepseek: boolean
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
}

export type ScanWithTargets = Scan & { targets: Target[] }
export type TargetWithDetails = Target & {
  tool_runs: ToolRun[]
  findings: Finding[]
}
export type FindingWithDetails = Finding & {
  ai_review: AIReview | null
  target_address: string
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

export const api = {
  getDashboard: () => request<DashboardData>('/api/dashboard'),

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
