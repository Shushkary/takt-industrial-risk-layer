import type { ButtonHTMLAttributes, ReactNode } from 'react'

type Variant = 'primary' | 'ghost' | 'danger'

const variantClass: Record<Variant, string> = {
  primary:
    'bg-[var(--teal-2)] text-[var(--bg-0)] hover:bg-[var(--teal-1)] border border-[var(--line-strong)]',
  ghost:
    'bg-transparent text-[var(--fg-1)] hover:bg-[var(--bg-2)] border border-[var(--line)]',
  danger:
    'bg-[var(--risk-high)] text-[var(--fg-1)] hover:opacity-90 border border-[var(--line-strong)]',
}

export function Button({
  children,
  variant = 'primary',
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { children: ReactNode; variant?: Variant }) {
  return (
    <button
      type="button"
      className={`rounded-takt px-3 py-1.5 text-[13px] font-medium transition-colors duration-150 ease-[cubic-bezier(0.2,0,0,1)] takt-focus-ring disabled:opacity-40 disabled:pointer-events-none ${variantClass[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  )
}
