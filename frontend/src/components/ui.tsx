import type { ReactNode } from 'react'

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string
  subtitle?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="flex items-start justify-between gap-4 mb-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-100">
          {title}
        </h1>
        {subtitle && (
          <div className="mt-1 text-sm text-slate-400">{subtitle}</div>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-slate-400 text-sm py-10">
      <span className="h-4 w-4 rounded-full border-2 border-slate-600 border-t-emerald-400 animate-spin" />
      {label || 'Loading…'}
    </div>
  )
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div className="card border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
      <span className="font-medium">Error:</span> {message}
    </div>
  )
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="card p-8 text-center text-sm text-slate-500">
      {children}
    </div>
  )
}

export function shortAddr(addr: string | number | null | undefined) {
  // Coerce defensively: callers sometimes pass a numeric id (e.g. target_id),
  // and calling string methods on a number throws and blanks the whole page.
  if (addr === null || addr === undefined || addr === '') return '—'
  const s = String(addr)
  if (s.length <= 14) return s
  return `${s.slice(0, 8)}…${s.slice(-6)}`
}

export function fmtDate(value: string | null | undefined) {
  if (!value) return '—'
  const d = new Date(value)
  if (isNaN(d.getTime())) return value
  return d.toLocaleString()
}
