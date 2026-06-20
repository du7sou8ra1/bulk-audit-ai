import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
}
interface State {
  error: Error | null
}

/**
 * Catches render-time exceptions in the routed page tree so a single bad
 * component shows a readable message instead of unmounting the whole app to a
 * blank white screen. The boundary is keyed on the route path in App, so it
 * resets automatically when the user navigates elsewhere.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface details in the browser console; no external reporting.
    console.error('Unhandled render error:', error, info)
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    return (
      <div className="card border-red-500/30 bg-red-500/5 p-6 text-sm text-red-300">
        <div className="mb-2 text-base font-semibold text-red-200">
          Something went wrong rendering this page.
        </div>
        <p className="mb-3 text-red-300/80">
          The rest of the app is fine — use the sidebar to navigate, or reload.
        </p>
        <pre className="mb-4 max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-slate-950/60 p-3 font-mono text-xs text-red-300/90">
          {error.message}
        </pre>
        <div className="flex gap-2">
          <button
            className="rounded-md bg-slate-800 px-3 py-1.5 text-slate-200 hover:bg-slate-700"
            onClick={() => this.setState({ error: null })}
          >
            Try again
          </button>
          <a
            href="/"
            className="rounded-md bg-slate-800 px-3 py-1.5 text-slate-200 hover:bg-slate-700"
          >
            Back to dashboard
          </a>
        </div>
      </div>
    )
  }
}
