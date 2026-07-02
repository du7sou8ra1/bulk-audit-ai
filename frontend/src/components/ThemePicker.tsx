import { useEffect, useRef, useState } from 'react'
import { THEMES, applyTheme, getStoredTheme, type ThemeId } from '../theme'

function Swatch({ bg, accent }: { bg: string; accent: string }) {
  return (
    <span
      className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-black/20 shadow-sm"
      style={{ background: bg }}
      aria-hidden
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: accent }} />
    </span>
  )
}

export default function ThemePicker() {
  const [open, setOpen] = useState(false)
  const [theme, setTheme] = useState<ThemeId>(getStoredTheme())
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const current = THEMES.find((t) => t.id === theme) ?? THEMES[0]
  const groups: Array<ThemeMetaGroup> = ['Base', 'Colored']

  function choose(id: ThemeId) {
    setTheme(id)
    applyTheme(id)
    setOpen(false)
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="flex w-full items-center gap-2 rounded-md border border-slate-700 bg-slate-800/60 px-3 py-2 text-sm text-slate-200 transition-colors hover:bg-slate-800"
      >
        <Swatch bg={current.bg} accent={current.accent} />
        <span className="flex-1 truncate text-left">{current.label}</span>
        <span className="text-xs text-slate-500">▾</span>
      </button>

      {open && (
        <div
          role="listbox"
          className="absolute bottom-full left-0 z-30 mb-2 max-h-[70vh] w-full overflow-auto rounded-lg border border-slate-700 bg-slate-900 py-1 shadow-xl shadow-black/40"
        >
          {groups.map((g) => (
            <div key={g}>
              <div className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                {g}
              </div>
              {THEMES.filter((t) => t.group === g).map((t) => {
                const active = t.id === theme
                return (
                  <button
                    key={t.id}
                    type="button"
                    role="option"
                    aria-selected={active}
                    onClick={() => choose(t.id)}
                    className={[
                      'flex w-full items-center gap-2.5 px-3 py-1.5 text-sm transition-colors',
                      active ? 'bg-emerald-500/10 text-emerald-400' : 'text-slate-300 hover:bg-slate-800',
                    ].join(' ')}
                  >
                    <Swatch bg={t.bg} accent={t.accent} />
                    <span className="flex-1 text-left">{t.label}</span>
                    {active && <span className="text-xs text-emerald-400">✓</span>}
                  </button>
                )
              })}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

type ThemeMetaGroup = 'Base' | 'Colored'
