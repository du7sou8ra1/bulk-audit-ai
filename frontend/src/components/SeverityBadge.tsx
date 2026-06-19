interface Props {
  severity: string | null | undefined
}

const STYLES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
}

export default function SeverityBadge({ severity }: Props) {
  const key = (severity || 'info').toLowerCase()
  const style = STYLES[key] || STYLES.info
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${style}`}
    >
      {severity || 'info'}
    </span>
  )
}
