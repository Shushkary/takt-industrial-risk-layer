import { useEffect, useState } from 'react'
import type { EntityCard } from '../../investigation/types'
import { SOURCE_COLORS, SOURCE_LABELS, operationLabel } from '../../investigation/types'

/**
 * Карточка сущности (ТЗ п. 5.5, п. 4.3): историчность активности и окружение
 * по узлу, пользователю или процессу — без ручного обхода отдельных консолей.
 */

type Props = {
  card: EntityCard | null
  loading: boolean
  error: string | null
  emptyHint: string
}

const TYPICALITY_LABELS: Record<string, { label: string; tone: string }> = {
  typical: { label: 'типичная активность', tone: 'var(--risk-low)' },
  atypical: { label: 'нетипичная активность', tone: 'var(--risk-high)' },
  first_seen: { label: 'наблюдается впервые', tone: 'var(--amber-1)' },
  unknown: { label: 'недостаточно данных', tone: 'var(--fg-3)' },
}

const ENTITY_LABELS: Record<string, string> = {
  host: 'Узел',
  user: 'Пользователь',
  process: 'Процесс',
}

function formatMoment(value: string): string {
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? value : new Date(parsed).toISOString().replace('T', ' ').slice(0, 19)
}

/** Гистограмма активности: столбики вырастают при смене сущности. */
function ActivityHistogram({ data }: { data: EntityCard['activity_by_hour'] }) {
  const [mounted, setMounted] = useState(false)
  useEffect(() => {
    setMounted(false)
    const timer = window.setTimeout(() => setMounted(true), 20)
    return () => window.clearTimeout(timer)
  }, [data])

  if (data.length === 0) {
    return <div className="text-[11px] text-[var(--fg-3)]">Нет данных об активности во времени</div>
  }
  const peak = Math.max(...data.map((item) => item.count), 1)

  return (
    <div className="flex h-[54px] items-end gap-[3px]" role="img" aria-label="Активность сущности по часам">
      {data.map((item, index) => {
        const ratio = item.count / peak
        return (
          <div
            key={item.bucket}
            className="flex-1 rounded-[2px] bg-[var(--teal-2)] transition-[height,opacity] duration-takt-slow ease-takt"
            style={{
              height: mounted ? `${Math.max(ratio * 100, item.count > 0 ? 8 : 3)}%` : '3%',
              opacity: item.count > 0 ? 0.45 + ratio * 0.55 : 0.18,
              transitionDelay: `${index * 22}ms`,
            }}
            title={`${item.bucket.slice(11, 16)} — событий: ${item.count}`}
          />
        )
      })}
    </div>
  )
}

export function EntityCardPanel({ card, loading, error, emptyHint }: Props) {
  if (loading) {
    return <div className="investigation-skeleton h-[220px] rounded-takt" aria-label="Загрузка карточки сущности" />
  }
  if (error) {
    return <div className="rounded-takt border border-[var(--risk-high)] p-3 text-[12px] text-[var(--fg-2)]">{error}</div>
  }
  if (!card) {
    return (
      <div className="rounded-takt border border-dashed border-[var(--line)] p-4 text-[12px] text-[var(--fg-3)]">
        {emptyHint}
      </div>
    )
  }

  const typicality = TYPICALITY_LABELS[card.typicality?.status ?? 'unknown'] ?? TYPICALITY_LABELS.unknown

  return (
    <div className="investigation-fade flex flex-col gap-3">
      <div>
        <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
          {ENTITY_LABELS[card.type] ?? card.type}
        </div>
        <div className="break-all font-mono text-[14px] text-[var(--fg-1)]">{card.id}</div>
      </div>

      <div
        className="flex items-center gap-2 rounded-takt border px-2.5 py-1.5 text-[12px]"
        style={{ borderColor: typicality.tone, color: 'var(--fg-1)' }}
      >
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: typicality.tone }} />
        <span className="font-medium">{typicality.label}</span>
      </div>
      <div className="text-[12px] text-[var(--fg-2)]">{card.typicality?.explanation}</div>

      <div>
        <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
          Историчность: активность по часам
        </div>
        <ActivityHistogram data={card.activity_by_hour ?? []} />
      </div>

      <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-[12px]">
        <dt className="text-[var(--fg-3)]">Событий</dt>
        <dd className="font-mono text-[var(--fg-1)]">{card.event_count}</dd>
        <dt className="text-[var(--fg-3)]">Впервые</dt>
        <dd className="font-mono text-[var(--fg-2)]">{formatMoment(card.first_seen)}</dd>
        <dt className="text-[var(--fg-3)]">Последний раз</dt>
        <dd className="font-mono text-[var(--fg-2)]">{formatMoment(card.last_seen)}</dd>
      </dl>

      <div>
        <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Источники</div>
        <div className="flex flex-wrap gap-1.5">
          {(card.sources ?? []).map((source) => (
            <span
              key={source}
              className="rounded-takt border px-1.5 py-0.5 text-[11px]"
              style={{ borderColor: SOURCE_COLORS[source] ?? 'var(--line)', color: 'var(--fg-1)' }}
            >
              {SOURCE_LABELS[source] ?? source}
            </span>
          ))}
        </div>
      </div>

      <div>
        <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
          Окружение ({card.environment_total})
        </div>
        <ul className="flex flex-col gap-1">
          {(card.environment ?? []).slice(0, 6).map((item) => (
            <li key={item.event_id} className="rounded-takt border border-[var(--line)] px-2 py-1.5 text-[11px]">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[var(--fg-1)]" title={item.operation}>{operationLabel(item.operation)}</span>
                <span style={{ color: SOURCE_COLORS[item.source] ?? 'var(--fg-3)' }}>
                  {SOURCE_LABELS[item.source] ?? item.source}
                </span>
              </div>
              <div className="font-mono text-[10px] text-[var(--fg-3)]">{formatMoment(item.observed_at)}</div>
            </li>
          ))}
          {(card.environment ?? []).length === 0 ? (
            <li className="text-[11px] text-[var(--fg-3)]">Сопутствующих событий не найдено</li>
          ) : null}
        </ul>
      </div>
    </div>
  )
}
