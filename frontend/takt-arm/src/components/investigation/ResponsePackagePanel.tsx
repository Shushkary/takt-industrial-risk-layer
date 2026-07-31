import { useMemo, useState } from 'react'
import { PackageCheck, ShieldAlert } from 'lucide-react'
import type { InvestigationArtifact } from '../../investigation/types'
import { SOURCE_COLORS, SOURCE_LABELS } from '../../investigation/types'

/**
 * Пакет реагирования (ТЗ п. 5.11, п. 4.8): набор артефактов с типом и узлом для
 * передачи на этап реагирования. Критичные действия не выполняются автоматически —
 * пакет только формируется и требует подтверждения аналитика (ТЗ п. 6.3).
 */

type Props = {
  artifacts: InvestigationArtifact[]
  caseId: string
  onConfirm: () => Promise<void>
  confirmed: boolean
  /** Демонстрационный режим: решение не уходит в backend. */
  localOnly: boolean
}

const TYPE_LABELS: Record<string, string> = {
  host: 'узел',
  file: 'файл',
  hash: 'хеш',
  process: 'процесс',
  account: 'учётная запись',
  address: 'адрес',
  url: 'URL',
  domain: 'домен',
}

export function ResponsePackagePanel({ artifacts, caseId, onConfirm, confirmed, localOnly }: Props) {
  const [selected, setSelected] = useState<Set<string>>(() => new Set(artifacts.map((item) => `${item.type}:${item.value}`)))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const grouped = useMemo(() => {
    const map = new Map<string, InvestigationArtifact[]>()
    for (const artifact of artifacts) {
      const list = map.get(artifact.type) ?? []
      list.push(artifact)
      map.set(artifact.type, list)
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [artifacts])

  const toggle = (key: string) => {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(key)) {
        next.delete(key)
      } else {
        next.add(key)
      }
      return next
    })
  }

  const payload = useMemo(
    () => ({
      case_id: caseId,
      generated_for: 'response',
      artifacts: artifacts
        .filter((item) => selected.has(`${item.type}:${item.value}`))
        .map((item) => ({ type: item.type, value: item.value, host_id: item.host_id ?? '', source: item.source ?? '' })),
    }),
    [artifacts, caseId, selected],
  )

  const download = () => {
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `response-package-${caseId}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  const confirm = async () => {
    setBusy(true)
    setError(null)
    try {
      await onConfirm()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось зафиксировать решение')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-start gap-2 rounded-takt border border-[var(--amber-2)] bg-[var(--bg-2)] px-2.5 py-2 text-[11px] text-[var(--fg-2)]">
        <ShieldAlert size={14} className="mt-[1px] shrink-0 text-[var(--amber-1)]" />
        <span>
          Пакет только формируется. Завершение процессов, блокировки и другие критичные действия выполняются на
          стороне средств реагирования и требуют подтверждения аналитика.
        </span>
      </div>

      {grouped.map(([type, items]) => (
        <div key={type}>
          <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
            {TYPE_LABELS[type] ?? type} ({items.length})
          </div>
          <ul className="flex flex-col gap-1">
            {items.map((item) => {
              const key = `${item.type}:${item.value}`
              const checked = selected.has(key)
              return (
                <li key={key}>
                  <label className="flex cursor-pointer items-start gap-2 rounded-takt border border-[var(--line)] px-2 py-1.5 transition-colors duration-takt hover:border-[var(--line-strong)]">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggle(key)}
                      className="takt-focus-ring mt-[3px] accent-[var(--teal-1)]"
                      aria-label={`Включить ${item.value} в пакет реагирования`}
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block break-all font-mono text-[11px] text-[var(--fg-1)]">{item.value}</span>
                      <span className="mt-0.5 flex items-center gap-2 text-[10px] text-[var(--fg-3)]">
                        {item.host_id ? <span>узел {item.host_id}</span> : null}
                        {item.source ? (
                          <span style={{ color: SOURCE_COLORS[item.source] ?? 'var(--fg-3)' }}>
                            {SOURCE_LABELS[item.source] ?? item.source}
                          </span>
                        ) : null}
                      </span>
                    </span>
                  </label>
                </li>
              )
            })}
          </ul>
        </div>
      ))}

      {artifacts.length === 0 ? (
        <div className="rounded-takt border border-dashed border-[var(--line)] px-2.5 py-3 text-[12px] text-[var(--fg-3)]">
          В кейсе ещё нет артефактов для передачи на реагирование.
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={download}
          disabled={payload.artifacts.length === 0}
          className="takt-focus-ring flex items-center gap-1.5 rounded-takt border border-[var(--line-strong)] bg-[var(--bg-2)] px-2.5 py-1.5 text-[12px] text-[var(--fg-1)] transition-colors duration-takt hover:border-[var(--teal-2)] disabled:cursor-not-allowed disabled:opacity-40"
        >
          <PackageCheck size={13} />
          Выгрузить пакет ({payload.artifacts.length})
        </button>
        <button
          type="button"
          onClick={confirm}
          disabled={busy || confirmed}
          className="takt-focus-ring rounded-takt border border-[var(--teal-2)] bg-[var(--teal-3)] px-2.5 py-1.5 text-[12px] text-[var(--fg-1)] transition-colors duration-takt hover:bg-[var(--teal-2)] disabled:cursor-not-allowed disabled:opacity-40"
        >
          {confirmed ? 'Инцидент подтверждён' : busy ? 'Фиксация…' : 'Подтвердить инцидент'}
        </button>
      </div>
      {localOnly ? (
        <div className="text-[11px] text-[var(--fg-3)]">
          Демонстрационный режим: решение не уходит в backend.
        </div>
      ) : null}
      {error ? <div className="text-[11px] text-[var(--risk-high)]">{error}</div> : null}
    </div>
  )
}
