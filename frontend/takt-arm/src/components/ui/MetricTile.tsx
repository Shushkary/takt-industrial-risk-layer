import type { ReactNode } from 'react'

export function MetricTile({
  label,
  value,
  hint,
}: {
  label: string
  value: ReactNode
  hint?: string
}) {
  return (
    <div className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
      <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">{label}</div>
      <div className="mt-1 font-mono text-[28px] leading-none text-[var(--fg-1)] tabular-nums">{value}</div>
      {hint ? <div className="mt-1 text-[12px] text-[var(--fg-2)]">{hint}</div> : null}
    </div>
  )
}
