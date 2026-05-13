function zoneForRisk(value: number): { label: string; bar: string; text: string } {
  if (value >= 0.9) return { label: 'Критично', bar: 'var(--risk-crit)', text: 'var(--risk-crit)' }
  if (value >= 0.7) return { label: 'Высокий', bar: 'var(--risk-high)', text: 'var(--risk-high)' }
  if (value >= 0.4) return { label: 'Средний', bar: 'var(--risk-mid)', text: 'var(--risk-mid)' }
  return { label: 'Низкий', bar: 'var(--risk-low)', text: 'var(--risk-low)' }
}

export function RiskBadge({ value, className = '' }: { value: number; className?: string }) {
  const z = zoneForRisk(value)
  const pct = Math.min(100, Math.max(0, value * 100))
  const text = value.toFixed(3).replace('.', ',')

  return (
    <div className={`flex flex-col gap-1 ${className}`} aria-label={`Risk Index ${text}, зона ${z.label}`}>
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[20px] leading-none tabular-nums" style={{ color: z.text }}>
          {text}
        </span>
        <span className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">{z.label}</span>
      </div>
      <div className="h-1 w-full bg-[var(--bg-2)]" role="presentation">
        <div className="h-1 rounded-takt" style={{ width: `${pct}%`, backgroundColor: z.bar }} />
      </div>
    </div>
  )
}
