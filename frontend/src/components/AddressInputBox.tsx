import { useMemo } from 'react'

interface Props {
  value: string
  onChange: (value: string) => void
  rows?: number
}

const ADDRESS_RE = /0x[a-fA-F0-9]{40}/g

export function parseAddresses(
  blob: string,
): { address: string; label: string }[] {
  const out: { address: string; label: string }[] = []
  const seen = new Set<string>()
  for (const rawLine of blob.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line) continue
    // optional "address,label" form
    const [addrPart, ...rest] = line.split(',')
    const addr = addrPart.trim()
    if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) continue
    const key = addr.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ address: addr, label: rest.join(',').trim() })
  }
  return out
}

export default function AddressInputBox({ value, onChange, rows = 12 }: Props) {
  const count = useMemo(() => {
    const matches = value.match(ADDRESS_RE)
    if (!matches) return 0
    return new Set(matches.map((m) => m.toLowerCase())).size
  }, [value])

  return (
    <div>
      <textarea
        className="input font-mono text-xs leading-relaxed resize-y"
        rows={rows}
        spellCheck={false}
        placeholder={
          '0xabc...123\n0xdef...456, my-label\nOne address per line. Optional "address,label".'
        }
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <div className="mt-1.5 flex items-center justify-between text-xs">
        <span className="text-slate-500">
          One address per line · optional{' '}
          <code className="text-slate-400">address,label</code>
        </span>
        <span className="text-emerald-400 font-medium">
          {count} valid 0x address{count === 1 ? '' : 'es'} detected
        </span>
      </div>
    </div>
  )
}
