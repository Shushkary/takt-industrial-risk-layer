import type { HTMLAttributes, ReactNode } from 'react'

export function Chip({
  children,
  active,
  className = '',
  ...props
}: HTMLAttributes<HTMLButtonElement> & { children: ReactNode; active?: boolean }) {
  return (
    <button
      type="button"
      className={`rounded-takt border px-2 py-0.5 text-[12px] transition-colors duration-150 ease-[cubic-bezier(0.2,0,0,1)] takt-focus-ring ${
        active
          ? 'border-[var(--teal-1)] bg-[var(--teal-3)] text-[var(--fg-1)]'
          : 'border-[var(--line)] bg-[var(--bg-1)] text-[var(--fg-2)] hover:border-[var(--line-strong)]'
      } ${className}`}
      {...props}
    >
      {children}
    </button>
  )
}
