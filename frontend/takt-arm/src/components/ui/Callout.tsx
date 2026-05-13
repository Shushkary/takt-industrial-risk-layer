import type { ReactNode } from 'react'

type CalloutTone = 'info' | 'warning' | 'danger'

const toneBorder: Record<CalloutTone, string> = {
  info: 'border-[var(--line-strong)]',
  warning: 'border-[var(--amber-2)]',
  danger: 'border-[var(--risk-high)]',
}

export function Callout({
  title,
  children,
  tone = 'info',
}: {
  title: string
  children: ReactNode
  tone?: CalloutTone
}) {
  return (
    <aside
      className={`rounded-takt border bg-[var(--bg-1)] p-3 ${toneBorder[tone]}`}
      role="note"
      aria-label={title}
    >
      <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">{title}</div>
      <div className="mt-2 text-[13px] text-[var(--fg-2)]">{children}</div>
    </aside>
  )
}
