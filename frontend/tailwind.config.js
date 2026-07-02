/** @type {import('tailwindcss').Config} */

// Structural + accent palettes are driven by CSS variables (see src/theme.css),
// so swapping [data-theme] on <html> re-themes the whole app. Each var holds a
// space-separated "R G B" triple; `<alpha-value>` keeps Tailwind opacity modifiers
// (e.g. bg-emerald-500/10) working.
const ch = (name) => `rgb(var(${name}) / <alpha-value>)`

const structural = {
  50: ch('--c-slate-50'),
  100: ch('--c-slate-100'),
  200: ch('--c-slate-200'),
  300: ch('--c-slate-300'),
  400: ch('--c-slate-400'),
  500: ch('--c-slate-500'),
  600: ch('--c-slate-600'),
  700: ch('--c-slate-700'),
  800: ch('--c-slate-800'),
  900: ch('--c-slate-900'),
  950: ch('--c-slate-950'),
}

const accent = {
  300: ch('--c-accent-400'),
  400: ch('--c-accent-400'),
  500: ch('--c-accent-500'),
  600: ch('--c-accent-600'),
  700: ch('--c-accent-700'),
}

export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Neutral structural palette (backgrounds, borders, text). zinc aliases it
        // so the handful of zinc-* usages theme consistently too.
        slate: structural,
        zinc: structural,
        // Accent (was emerald). Every emerald-* utility now follows the theme accent.
        emerald: accent,
        // Foreground for solid accent surfaces (primary button text): light on dark
        // accents, dark on bright accents — set per theme.
        accentfg: ch('--c-accent-fg'),
      },
      fontFamily: {
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          '"Liberation Mono"',
          '"Courier New"',
          'monospace',
        ],
      },
    },
  },
  plugins: [],
}
