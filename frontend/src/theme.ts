// Theme registry + apply/persist. Themes are pure CSS-variable swaps driven by the
// [data-theme] attribute on <html> (see index.css + tailwind.config.js), so switching
// is instant and needs no React context.

export type ThemeId =
  | 'dark'
  | 'light'
  | 'dracula'
  | 'nord'
  | 'monokai'
  | 'solarized-dark'
  | 'github-light'
  | 'gruvbox-dark'

export interface ThemeMeta {
  id: ThemeId
  label: string
  group: 'Base' | 'Colored'
  /** panel background + accent, for the picker preview swatch */
  bg: string
  accent: string
}

export const THEMES: ThemeMeta[] = [
  { id: 'dark', label: 'Dark', group: 'Base', bg: '#0f172a', accent: '#10b981' },
  { id: 'light', label: 'Light', group: 'Base', bg: '#ffffff', accent: '#059669' },
  { id: 'dracula', label: 'Dracula', group: 'Colored', bg: '#282a36', accent: '#bd93f9' },
  { id: 'nord', label: 'Nord', group: 'Colored', bg: '#2e3440', accent: '#88c0d0' },
  { id: 'monokai', label: 'Monokai', group: 'Colored', bg: '#272822', accent: '#a6e22e' },
  { id: 'solarized-dark', label: 'Solarized Dark', group: 'Colored', bg: '#002b36', accent: '#268bd2' },
  { id: 'github-light', label: 'GitHub Light', group: 'Colored', bg: '#ffffff', accent: '#0969da' },
  { id: 'gruvbox-dark', label: 'Gruvbox', group: 'Colored', bg: '#282828', accent: '#fe8019' },
]

export const THEME_STORAGE_KEY = 'bulkauditai-theme'
const DEFAULT_THEME: ThemeId = 'dark'
const VALID = new Set(THEMES.map((t) => t.id))

export function getStoredTheme(): ThemeId {
  try {
    const v = localStorage.getItem(THEME_STORAGE_KEY) as ThemeId | null
    if (v && VALID.has(v)) return v
  } catch {
    /* localStorage unavailable */
  }
  return DEFAULT_THEME
}

export function applyTheme(id: ThemeId, persist = true): void {
  document.documentElement.setAttribute('data-theme', id)
  if (persist) {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, id)
    } catch {
      /* ignore */
    }
  }
}

/** Apply the stored (or default) theme without re-persisting. Safe to call on boot. */
export function initTheme(): void {
  applyTheme(getStoredTheme(), false)
}
