interface Props {
  // current stage id; anything before it is "done"
  current?: string | null
}

const STAGES = [
  { id: 'fetch', label: 'Fetch' },
  { id: 'proxy', label: 'Proxy' },
  { id: 'detect', label: 'Detect' },
  { id: 'tools', label: 'Tools' },
  { id: 'ai', label: 'AI' },
  { id: 'done', label: 'Done' },
]

export default function ProgressTimeline({ current }: Props) {
  const currentIdx = current
    ? STAGES.findIndex((s) => s.id === current.toLowerCase())
    : -1

  return (
    <div className="flex items-center gap-1.5">
      {STAGES.map((stage, i) => {
        const done = currentIdx >= 0 && i < currentIdx
        const active = currentIdx >= 0 && i === currentIdx
        return (
          <div key={stage.id} className="flex items-center gap-1.5">
            <div className="flex flex-col items-center gap-1">
              <div
                className={[
                  'h-2.5 w-2.5 rounded-full border',
                  done
                    ? 'bg-emerald-500 border-emerald-500'
                    : active
                      ? 'bg-emerald-400/30 border-emerald-400 animate-pulse'
                      : 'bg-slate-800 border-slate-700',
                ].join(' ')}
              />
              <span
                className={[
                  'text-[10px] uppercase tracking-wide',
                  done || active ? 'text-slate-300' : 'text-slate-600',
                ].join(' ')}
              >
                {stage.label}
              </span>
            </div>
            {i < STAGES.length - 1 && (
              <div
                className={[
                  'h-px w-6 -mt-4',
                  done ? 'bg-emerald-500' : 'bg-slate-700',
                ].join(' ')}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}
