import type { HTMLAttributes, ReactNode } from 'react'

export function StatusPill({ children, tone = 'neutral', className = '' }: HTMLAttributes<HTMLSpanElement> & { children: ReactNode; tone?: 'neutral' | 'teal' | 'amber' | 'risk' }) {
  const tones: Record<'neutral' | 'teal' | 'amber' | 'risk', string> = {
    neutral: 'border-[var(--line)] bg-[var(--bg-2)] text-[var(--fg-2)]',
    teal: 'border-[var(--teal-2)] bg-[var(--teal-3)] text-[var(--fg-1)]',
    amber: 'border-[var(--amber-2)] bg-[var(--bg-2)] text-[var(--amber-1)]',
    risk: 'border-[var(--risk-high)] bg-[var(--bg-2)] text-[var(--risk-high)]',
  }

  return (
    <span
      className={`inline-flex items-center rounded-takt border px-2 py-0.5 text-[11px] font-medium uppercase tracking-[0.06em] ${tones[tone]} ${className}`}
    >
      {children}
    </span>
  )
}
