interface Props {
  status: string | null | undefined
}

const STYLES: Record<string, string> = {
  // scan statuses
  queued: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
  running: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  completed: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  failed: 'bg-red-500/15 text-red-400 border-red-500/30',
  cancelled: 'bg-zinc-600/20 text-zinc-400 border-zinc-600/40',
  // tool-run / target statuses
  pending: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
  ok: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  timeout: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  skipped: 'bg-zinc-600/20 text-zinc-400 border-zinc-600/40',
}

export default function StatusBadge({ status }: Props) {
  const key = (status || 'pending').toLowerCase()
  const style = STYLES[key] || STYLES.pending
  const pulse = key === 'running'
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium ${style}`}
    >
      {pulse && (
        <span className="h-1.5 w-1.5 rounded-full bg-current animate-pulse" />
      )}
      {status || 'pending'}
    </span>
  )
}
