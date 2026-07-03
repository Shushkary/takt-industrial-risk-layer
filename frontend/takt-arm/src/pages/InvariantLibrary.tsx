import { useEffect, useMemo, useState } from 'react'
import { Button } from '../components/ui/Button'
import { Chip } from '../components/ui/Chip'
import {
  fetchComplianceMode,
  fetchEventSourcesCatalog,
  fetchInvariants,
  taktApiConfigured,
  type ComplianceModeResponse,
  type InvariantCatalogItem,
} from '../app/taktApi'
import { demoIncidents, demoInvariantGroups } from '../demo'

type Period = '1 день' | '3 дня' | '1 неделя' | '1 месяц'
type InvariantRow = {
  group: string
  id: string
  name: string
  weight: string
  threshold: string
  triggerCount: number | null
  experimental: boolean
}

const periods: Period[] = ['1 день', '3 дня', '1 неделя', '1 месяц']

function complianceEnabled(mode: ComplianceModeResponse | null): boolean {
  return mode?.compliance_enabled === true
}

export function InvariantLibrary() {
  const [period, setPeriod] = useState<Period>('3 дня')
  const [reportText, setReportText] = useState('')
  const [apiInvariants, setApiInvariants] = useState<InvariantCatalogItem[] | null>(null)
  const [complianceMode, setComplianceMode] = useState<ComplianceModeResponse | null>(null)
  const [eventSourcesCount, setEventSourcesCount] = useState<number | null>(null)
  const [loadState, setLoadState] = useState<'local' | 'loading' | 'loaded' | 'error'>(
    taktApiConfigured() ? 'loading' : 'local',
  )

  useEffect(() => {
    let cancelled = false
    if (!taktApiConfigured()) {
      setApiInvariants(null)
      setComplianceMode(null)
      setLoadState('local')
      return
    }
    setLoadState('loading')
    Promise.all([fetchInvariants(), fetchEventSourcesCatalog(), fetchComplianceMode()])
      .then(([items, eventSources, mode]) => {
        if (cancelled) {
          return
        }
        setApiInvariants(items ?? [])
        setEventSourcesCount(eventSources ? Object.keys(eventSources).length : null)
        setComplianceMode(mode)
        setLoadState('loaded')
      })
      .catch(() => {
        if (!cancelled) {
          setApiInvariants([])
          setComplianceMode(null)
          setEventSourcesCount(null)
          setLoadState('error')
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  const invariantRows = useMemo<InvariantRow[]>(() => {
    if (apiInvariants) {
      return apiInvariants.map((item) => {
        const name = item.title_ru || item.id
        return {
          group: item.block_label_ru || item.block_key || 'API',
          id: item.id,
          name,
          weight: 'не задан сервером',
          threshold: 'не задан сервером',
          triggerCount: null,
          experimental: item.experimental,
        }
      })
    }
    return demoInvariantGroups.flatMap(([group, ...items]) =>
      items.map((name, index) => {
        const triggerCount = demoIncidents.filter((incident) =>
          incident.invariant.toLocaleLowerCase('ru-RU').includes(name.toLocaleLowerCase('ru-RU').slice(0, 10)),
        ).length
        return {
          group,
          id: `${group}-${name}`,
          name,
          weight: `0,${String((index + 2) * 7).padStart(2, '0')}`,
          threshold: index % 2 === 0 ? '0,700' : '0,500',
          triggerCount,
          experimental: false,
        }
      }),
    )
  }, [apiInvariants])

  const invariantGroups = useMemo(() => {
    const groups = new Map<string, typeof invariantRows>()
    for (const row of invariantRows) {
      groups.set(row.group, [...(groups.get(row.group) ?? []), row])
    }
    return Array.from(groups.entries())
  }, [invariantRows])
  const invariantCount = invariantRows.length
  const isApiCatalog = apiInvariants !== null
  const localReportBlocked = complianceEnabled(complianceMode)

  function buildReport(): string {
    return [
      'NON-EVIDENCE LOCAL UI REPORT',
      'Этот отчёт сформирован в браузере и не является машинно-проверяемым forensic-артефактом.',
      '',
      'Отчёт библиотеки инвариантов ТАКТ',
      `Период истории: ${period}`,
      `Всего инвариантов: ${invariantCount}`,
      '',
      ...invariantRows.map((row) => {
        const triggerText = row.triggerCount === null ? 'не рассчитывается локально для API-каталога' : String(row.triggerCount)
        return `${row.group}; ${row.name}; вес ${row.weight}; порог ${row.threshold}; срабатываний за период ${triggerText}`
      }),
    ].join('\n')
  }

  function prepareReport() {
    if (localReportBlocked) {
      setReportText('NON-EVIDENCE LOCAL UI REPORT\nCompliance mode блокирует локальные отчёты по инвариантам. Для машинно-проверяемых артефактов используйте backend evidence и forensic API.')
      return
    }
    setReportText(buildReport())
  }

  function exportReport() {
    if (localReportBlocked) {
      setReportText('NON-EVIDENCE LOCAL UI REPORT\nCompliance mode блокирует локальные отчёты по инвариантам. Для машинно-проверяемых артефактов используйте backend evidence и forensic API.')
      return
    }
    const text = reportText || buildReport()
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'non-evidence-local-ui-report.txt'
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
    setReportText(text)
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">Библиотека инвариантов</h1>
      <p className="max-w-[72ch] text-[13px] text-[var(--fg-2)]">
        Справочник {invariantCount} инвариантов сгруппирован по шести блокам. В интерфейсе доступен только просмотр и аудит конфигурации.
        {isApiCatalog ? ' В API-режиме веса, пороги и срабатывания показываются только если они пришли от сервера; локальные расчёты не подмешиваются.' : ''}
      </p>
      <div className="flex flex-wrap items-center gap-2">
        {periods.map((item) => (
          <Chip key={item} active={period === item} onClick={() => setPeriod(item)}>
            {item}
          </Chip>
        ))}
        <Button onClick={prepareReport} disabled={localReportBlocked}>Сформировать отчёт</Button>
        <Button variant="ghost" onClick={exportReport} disabled={localReportBlocked}>
          Выгрузить отчёт
        </Button>
      </div>
      {localReportBlocked ? (
        <p className="text-[12px] text-[var(--fg-3)]">
          Compliance mode блокирует локальные отчёты по инвариантам. Доказательность должна приходить из backend forensic и audit API.
        </p>
      ) : null}
      {reportText ? (
        <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3 font-mono text-[12px] text-[var(--fg-2)]">
          {reportText}
        </pre>
      ) : null}
      <p className="text-[12px] text-[var(--fg-3)]">
        {loadState === 'loaded'
          ? `API: /invariants и /catalog/event-sources${eventSourcesCount === null ? '' : ` (${eventSourcesCount} источников)`}.`
          : loadState === 'loading'
            ? 'API: /invariants загружается.'
            : loadState === 'error'
              ? 'API: /invariants недоступен; backend-каталог не отображается.'
              : 'Локальный демо-каталог.'}
      </p>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {invariantGroups.map(([title, items]) => (
          <section key={title} className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
            <h2 className="text-[13px] font-semibold text-[var(--fg-1)]">{title}</h2>
            <div className="mt-3 flex flex-col gap-2">
              {items.map((row) => (
                <article key={row.id} className="border border-[var(--line)] bg-[var(--bg-0)] p-2 text-[12px] text-[var(--fg-2)]">
                  <b className="block text-[var(--fg-1)]">{row.name}</b>
                  <span>
                    {isApiCatalog
                      ? 'Описание получено из каталога API; локальные веса, пороги и счётчики не используются.'
                      : 'Описание: проверка отклонения от эксплуатационного инварианта выбранного блока.'}
                  </span>
                  <span className="mt-1 block">
                    ID {row.id} · Вес {row.weight} · порог {row.threshold} · срабатываний за период {row.triggerCount === null ? 'не рассчитывается локально' : row.triggerCount} · {row.experimental ? 'экспериментальный' : 'стабильный'}
                  </span>
                </article>
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  )
}
