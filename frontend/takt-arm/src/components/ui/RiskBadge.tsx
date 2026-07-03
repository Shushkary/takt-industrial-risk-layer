import { formatRisk } from '../../app/format'

function zoneForRisk(value: number): { label: string; bar: string; text: string } {
  if (value >= 0.9) return { label: 'Критично', bar: 'var(--risk-crit)', text: 'var(--risk-crit)' }
  if (value >= 0.7) return { label: 'Высокий', bar: 'var(--risk-high)', text: 'var(--risk-high)' }
  if (value >= 0.4) return { label: 'Средний', bar: 'var(--risk-mid)', text: 'var(--risk-mid)' }
  return { label: 'Низкий', bar: 'var(--risk-low)', text: 'var(--risk-low)' }
}

export function RiskBadge({ value, className = '' }: { value: number; className?: string }) {
  const zone = zoneForRisk(value)
  const percent = Math.min(100, Math.max(0, value * 100))
  const text = formatRisk(value)

  return (
    <div className={`flex flex-col gap-1 ${className}`} aria-label={`Индекс риска ${text}, зона ${zone.label}`}>
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[20px] leading-none tabular-nums" style={{ color: zone.text }}>
          {text}
        </span>
        <span className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">{zone.label}</span>
      </div>
      <div className="h-1 w-full bg-[var(--bg-2)]" role="presentation">
        <div className="h-1 rounded-takt" style={{ width: `${percent}%`, backgroundColor: zone.bar }} />
      </div>
    </div>
  )
}
