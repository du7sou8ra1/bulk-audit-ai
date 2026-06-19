interface Props {
  data: unknown
  maxHeight?: string
}

export default function ToolOutputViewer({ data, maxHeight = '24rem' }: Props) {
  let text: string
  if (data == null) {
    text = '(empty)'
  } else if (typeof data === 'string') {
    text = data
  } else {
    try {
      text = JSON.stringify(data, null, 2)
    } catch {
      text = String(data)
    }
  }

  return (
    <pre
      className="overflow-auto rounded-md bg-slate-950 border border-slate-800 p-3 text-xs leading-relaxed text-slate-300 font-mono whitespace-pre-wrap break-words"
      style={{ maxHeight }}
    >
      {text}
    </pre>
  )
}
