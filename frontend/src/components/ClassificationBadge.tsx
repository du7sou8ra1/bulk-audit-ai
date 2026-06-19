import type { Classification } from '../api'

interface Props {
  classification: Classification | string | null | undefined
}

const STYLES: Record<string, string> = {
  CONFIRMED_CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  LIKELY_CRITICAL_NEEDS_POC:
    'bg-orange-500/15 text-orange-400 border-orange-500/30',
  NEEDS_MORE_INVESTIGATION:
    'bg-amber-500/15 text-amber-400 border-amber-500/30',
  LOW_OR_INFO: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
  FALSE_POSITIVE:
    'bg-zinc-700/30 text-zinc-500 border-zinc-600/40 line-through',
}

const LABELS: Record<string, string> = {
  CONFIRMED_CRITICAL: 'Confirmed critical',
  LIKELY_CRITICAL_NEEDS_POC: 'Likely critical · needs PoC',
  NEEDS_MORE_INVESTIGATION: 'Needs investigation',
  LOW_OR_INFO: 'Low / info',
  FALSE_POSITIVE: 'False positive',
}

export default function ClassificationBadge({ classification }: Props) {
  if (!classification) {
    return <span className="text-xs text-slate-500">—</span>
  }
  const style = STYLES[classification] || STYLES.LOW_OR_INFO
  const label = LABELS[classification] || classification
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${style}`}
    >
      {label}
    </span>
  )
}
