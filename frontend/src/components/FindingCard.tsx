import { Link } from 'react-router-dom'
import type { Finding } from '../api'
import SeverityBadge from './SeverityBadge'
import ClassificationBadge from './ClassificationBadge'

interface Props {
  finding: Finding
}

function score(value: number | null | undefined) {
  if (value == null) return '—'
  return value.toFixed(1)
}

export default function FindingCard({ finding }: Props) {
  return (
    <Link
      to={`/findings/${finding.id}`}
      className="card block p-4 hover:border-slate-600 transition-colors"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity_candidate} />
            <ClassificationBadge classification={finding.classification} />
          </div>
          <h3 className="mt-2 font-medium text-slate-100 truncate">
            {finding.title}
          </h3>
          <p className="mt-1 text-xs text-slate-500 font-mono">
            {finding.detector}
          </p>
        </div>
        <div className="flex shrink-0 gap-4 text-right">
          <div>
            <div className="text-[10px] uppercase tracking-wide text-slate-500">
              Impact
            </div>
            <div className="text-lg font-semibold text-slate-100">
              {score(finding.impact_score)}
            </div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wide text-slate-500">
              Conf.
            </div>
            <div className="text-lg font-semibold text-slate-100">
              {score(finding.confidence_score)}
            </div>
          </div>
        </div>
      </div>
      {finding.description && (
        <p className="mt-2 text-sm text-slate-400 line-clamp-2">
          {finding.description}
        </p>
      )}
    </Link>
  )
}
