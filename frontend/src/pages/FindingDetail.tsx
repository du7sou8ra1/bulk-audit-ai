import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, type FindingWithDetails } from '../api'
import { PageHeader, Spinner, ErrorBox, fmtDate } from '../components/ui'
import SeverityBadge from '../components/SeverityBadge'
import ClassificationBadge from '../components/ClassificationBadge'
import ToolOutputViewer from '../components/ToolOutputViewer'

function ScoreBox({ label, value }: { label: string; value: number }) {
  return (
    <div className="card p-4 text-center">
      <div className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-1 text-3xl font-semibold text-slate-100">
        {value != null ? value.toFixed(1) : '—'}
        <span className="text-base text-slate-500"> / 10</span>
      </div>
    </div>
  )
}

function stepText(step: unknown): string {
  if (typeof step === 'string') return step
  if (step && typeof step === 'object') {
    const o = step as Record<string, unknown>
    return String(o.title ?? o.name ?? o.test ?? o.description ?? JSON.stringify(step))
  }
  return String(step)
}

export default function FindingDetail() {
  const { id = '' } = useParams()
  const [finding, setFinding] = useState<FindingWithDetails | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [updating, setUpdating] = useState(false)
  const [showRaw, setShowRaw] = useState(false)

  useEffect(() => {
    let active = true
    api
      .getFinding(id)
      .then((f) => active && setFinding(f))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false))
    return () => {
      active = false
    }
  }, [id])

  async function setStatus(status: string) {
    setUpdating(true)
    try {
      const updated = await api.setFindingStatus(id, status)
      setFinding((prev) => (prev ? { ...prev, ...updated } : prev))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setUpdating(false)
    }
  }

  if (loading) return <Spinner label="Loading finding…" />
  if (error && !finding) return <ErrorBox message={error} />
  if (!finding) return <ErrorBox message="Finding not found." />

  const review = finding.ai_review
  const nextTests = Array.isArray(finding.next_tests_json)
    ? finding.next_tests_json
    : []
  const aiSteps = review && Array.isArray(review.recommended_next_steps)
    ? review.recommended_next_steps
    : []

  return (
    <div>
      <PageHeader
        title={finding.title}
        subtitle={
          <span className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity_candidate} />
            <ClassificationBadge classification={finding.classification} />
            <span className="text-slate-500">·</span>
            <span className="font-mono text-xs">{finding.detector}</span>
            <span className="text-slate-500">·</span>
            <Link
              to={`/targets/${finding.target_id}`}
              className="font-mono text-xs text-emerald-400 hover:underline break-all"
            >
              {finding.target_address}
            </Link>
          </span>
        }
        actions={
          <a
            href={api.exportFindingMarkdownUrl(id)}
            target="_blank"
            rel="noreferrer"
            className="btn-secondary"
          >
            Export Markdown
          </a>
        }
      />

      {error && (
        <div className="mb-4">
          <ErrorBox message={error} />
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 mb-6 max-w-sm">
        <ScoreBox label="Impact" value={finding.impact_score} />
        <ScoreBox label="Confidence" value={finding.confidence_score} />
      </div>

      {/* Status actions */}
      <div className="card p-4 mb-6">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="text-sm text-slate-400">
            Current status:{' '}
            <span className="text-slate-100 font-medium">{finding.status}</span>
          </div>
          <div className="flex gap-2">
            <button
              className="btn-secondary"
              disabled={updating}
              onClick={() => setStatus('FALSE_POSITIVE')}
            >
              Mark False Positive
            </button>
            <button
              className="btn-secondary"
              disabled={updating}
              onClick={() => setStatus('NEEDS_MORE_INVESTIGATION')}
            >
              Mark Needs More Investigation
            </button>
            <button
              className="btn-primary"
              disabled={updating}
              onClick={() => setStatus('CONFIRMED_CRITICAL')}
            >
              Mark Confirmed
            </button>
          </div>
        </div>
      </div>

      {/* Description */}
      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Description
        </h2>
        <div className="card p-4 text-sm text-slate-300 whitespace-pre-wrap">
          {finding.description || '—'}
        </div>
      </section>

      {/* Evidence */}
      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Evidence
        </h2>
        <ToolOutputViewer data={finding.evidence_json} />
      </section>

      {/* Next tests */}
      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Next tests
        </h2>
        {nextTests.length === 0 ? (
          <p className="text-sm text-slate-500">No suggested tests.</p>
        ) : (
          <ul className="card divide-y divide-slate-800">
            {nextTests.map((t, i) => (
              <li key={i} className="px-4 py-2.5 text-sm text-slate-300">
                {stepText(t)}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* AI review */}
      <section className="mb-6">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
          AI review
        </h2>
        {!review ? (
          <p className="text-sm text-slate-500">
            No AI review for this finding.
          </p>
        ) : (
          <div className="card p-4 space-y-4">
            <div className="flex items-center gap-3 flex-wrap text-sm">
              <span className="text-slate-500">Model:</span>
              <span className="font-mono text-slate-300">{review.model}</span>
              {review.classification && (
                <ClassificationBadge classification={review.classification} />
              )}
              <span className="text-xs text-slate-500">
                {fmtDate(review.created_at)}
              </span>
            </div>

            {review.rationale && (
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">
                  Rationale
                </div>
                <p className="text-sm text-slate-300 whitespace-pre-wrap">
                  {review.rationale}
                </p>
              </div>
            )}

            {aiSteps.length > 0 && (
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">
                  Recommended next steps
                </div>
                <ul className="list-disc list-inside space-y-1 text-sm text-slate-300">
                  {aiSteps.map((s, i) => (
                    <li key={i}>{stepText(s)}</li>
                  ))}
                </ul>
              </div>
            )}

            <div>
              <button
                className="text-xs text-emerald-400 hover:underline"
                onClick={() => setShowRaw((s) => !s)}
              >
                {showRaw ? 'Hide' : 'Show'} raw response
              </button>
              {showRaw && (
                <div className="mt-2">
                  <ToolOutputViewer data={review.response_json} />
                </div>
              )}
            </div>
          </div>
        )}
      </section>
    </div>
  )
}
