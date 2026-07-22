import { FormEvent, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Button } from '../components/ui/Button'
import { Chip } from '../components/ui/Chip'
import {
  fetchCases,
  fetchEventSearch,
  taktApiConfigured,
  type CaseListItem,
  type EventSearchItem,
  type EventSearchQuery,
} from '../app/taktApi'
import { demoIncidents } from '../demo'

type SearchState = 'idle' | 'loading' | 'loaded' | 'error'
type Result =
  | { kind: 'event'; id: string; at: string; title: string; subtitle: string; event: EventSearchItem }
  | { kind: 'case'; id: string; at: string; title: string; subtitle: string; caseRow: CaseListItem }

const sourceOptions = ['', 'edr', 'siem', 'ndr', 'ot', 'auth_logs', 'network_events', 'plc_polling', 'service_desk']

function param(searchParams: URLSearchParams, name: string): string {
  return searchParams.get(name)?.trim() ?? ''
}

function eventLabel(event: EventSearchItem): string {
  return [event.operation, event.protocol, event.source].filter(Boolean).join(' · ')
}

function entityPairs(event: EventSearchItem): Array<[string, string]> {
  if (!event.entities) {
    return []
  }
  return Object.entries(event.entities)
    .filter(([, value]) => typeof value === 'string' && value.trim() !== '')
    .map(([key, value]) => [key, String(value)])
}

function caseMatches(row: CaseListItem, query: string): boolean {
  if (!query) {
    return true
  }
  const needle = query.toLowerCase()
  return [row.case_id, row.title, row.primary_asset_id, row.trigger_operation, row.operator_id]
    .filter((value): value is string => typeof value === 'string')
    .some((value) => value.toLowerCase().includes(needle))
}

export function UnifiedSearch() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [query, setQuery] = useState(param(searchParams, 'q'))
  const [source, setSource] = useState(param(searchParams, 'source'))
  const [hostId, setHostId] = useState(param(searchParams, 'host_id'))
  const [userId, setUserId] = useState(param(searchParams, 'user_id'))
  const [processId, setProcessId] = useState(param(searchParams, 'process_id'))
  const [address, setAddress] = useState(param(searchParams, 'address'))
  const [events, setEvents] = useState<EventSearchItem[]>([])
  const [cases, setCases] = useState<CaseListItem[]>([])
  const [totalEvents, setTotalEvents] = useState<number | null>(null)
  const [totalCases, setTotalCases] = useState<number | null>(null)
  const [state, setState] = useState<SearchState>('idle')
  const [error, setError] = useState('')
  const apiMode = taktApiConfigured()

  const apiQuery = useMemo<EventSearchQuery>(
    () => ({
      text: query || undefined,
      source: source || undefined,
      host_id: hostId || undefined,
      user_id: userId || undefined,
      process_id: processId || undefined,
      address: address || undefined,
      limit: 50,
      offset: 0,
    }),
    [address, hostId, processId, query, source, userId],
  )

  useEffect(() => {
    setQuery(param(searchParams, 'q'))
    setSource(param(searchParams, 'source'))
    setHostId(param(searchParams, 'host_id'))
    setUserId(param(searchParams, 'user_id'))
    setProcessId(param(searchParams, 'process_id'))
    setAddress(param(searchParams, 'address'))
  }, [searchParams])

  useEffect(() => {
    let cancelled = false
    if (!apiMode) {
      setEvents([])
      setCases([])
      setTotalEvents(null)
      setTotalCases(null)
      setState('loaded')
      setError('')
      return
    }
    setState('loading')
    setError('')
    Promise.all([
      fetchEventSearch(apiQuery),
      fetchCases({ case_id_prefix: query || undefined, limit: 25, offset: 0, sort: 'created_at_desc' }),
    ])
      .then(([eventResult, caseResult]) => {
        if (cancelled) {
          return
        }
        setEvents(eventResult?.items ?? [])
        setCases((caseResult?.items ?? []).filter((item) => caseMatches(item, query)))
        setTotalEvents(eventResult?.total ?? null)
        setTotalCases(caseResult?.total ?? null)
        setState('loaded')
      })
      .catch((cause) => {
        if (!cancelled) {
          setEvents([])
          setCases([])
          setTotalEvents(null)
          setTotalCases(null)
          setError(cause instanceof Error ? cause.message : 'Ошибка поиска')
          setState('error')
        }
      })
    return () => {
      cancelled = true
    }
  }, [apiMode, apiQuery, query])

  const localCases = useMemo(
    () =>
      demoIncidents
        .filter((incident) => caseMatches({ case_id: incident.id, title: incident.summary, primary_asset_id: incident.node }, query))
        .map((incident): CaseListItem => ({
          case_id: incident.id,
          title: incident.summary,
          risk_score: incident.risk,
          risk_class: incident.risk >= 0.7 ? 'high' : incident.risk >= 0.4 ? 'medium' : 'low',
          status: incident.status,
          primary_asset_id: incident.node,
          trigger_operation: incident.invariant,
          operator_id: incident.operator,
        })),
    [query],
  )

  const results = useMemo<Result[]>(() => {
    const eventResults = events.map((event): Result => ({
      kind: 'event',
      id: event.event_id,
      at: event.observed_at,
      title: eventLabel(event),
      subtitle: entityPairs(event)
        .slice(0, 4)
        .map(([key, value]) => `${key}=${value}`)
        .join(' · '),
      event,
    }))
    const caseResults = (apiMode ? cases : localCases).map((row): Result => ({
      kind: 'case',
      id: row.case_id,
      at: '',
      title: row.title ?? row.case_id,
      subtitle: [row.primary_asset_id, row.trigger_operation, row.status].filter(Boolean).join(' · '),
      caseRow: row,
    }))
    return [...eventResults, ...caseResults].sort((left, right) => right.at.localeCompare(left.at))
  }, [apiMode, cases, events, localCases])

  function updateParams(next: Record<string, string>) {
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(next)) {
      if (value.trim()) {
        params.set(key, value.trim())
      }
    }
    setSearchParams(params)
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    updateParams({ q: query, source, host_id: hostId, user_id: userId, process_id: processId, address })
  }

  function setEntityFilter(key: string, value: string) {
    const next = { q: query, source, host_id: hostId, user_id: userId, process_id: processId, address }
    if (key === 'host_id' || key === 'user_id' || key === 'process_id' || key === 'address') {
      next[key] = value
    }
    updateParams(next)
  }

  function reset() {
    setQuery('')
    setSource('')
    setHostId('')
    setUserId('')
    setProcessId('')
    setAddress('')
    setSearchParams(new URLSearchParams())
  }

  return (
    <div className="flex flex-col gap-4" data-testid="unified-search">
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-[280px] flex-1">
          <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">Единый поиск</h1>
          <p className="mt-1 text-[13px] text-[var(--fg-2)]">
            События и кейсы в одном списке: фильтр по сущностям открывает контекст без ручного копирования идентификаторов.
          </p>
        </div>
        <span className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] px-2 py-1 font-mono text-[12px] text-[var(--fg-2)]">
          {apiMode ? 'API: /events/search + /cases' : 'local-demo'}
        </span>
      </div>

      <form className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3" onSubmit={submit}>
        <div className="grid gap-2 xl:grid-cols-[minmax(260px,1fr)_160px_160px_160px_160px_160px_auto]">
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Строка поиска, case_id или фрагмент payload"
            className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring"
          />
          <select
            value={source}
            onChange={(event) => setSource(event.target.value)}
            className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-2 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring"
          >
            {sourceOptions.map((item) => (
              <option key={item || 'all'} value={item}>
                {item || 'Все источники'}
              </option>
            ))}
          </select>
          <input value={hostId} onChange={(event) => setHostId(event.target.value)} placeholder="host_id" className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring" />
          <input value={userId} onChange={(event) => setUserId(event.target.value)} placeholder="user_id" className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring" />
          <input value={processId} onChange={(event) => setProcessId(event.target.value)} placeholder="process_id" className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring" />
          <input value={address} onChange={(event) => setAddress(event.target.value)} placeholder="address" className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring" />
          <div className="flex gap-2">
            <Button type="submit">Найти</Button>
            <Button type="button" variant="ghost" onClick={reset}>Сброс</Button>
          </div>
        </div>
      </form>

      <div className="grid gap-3 md:grid-cols-3">
        <div className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
          <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">События</div>
          <div className="mt-1 font-mono text-[24px] text-[var(--fg-1)]">{apiMode ? (totalEvents ?? events.length) : 0}</div>
        </div>
        <div className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
          <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Кейсы</div>
          <div className="mt-1 font-mono text-[24px] text-[var(--fg-1)]">{apiMode ? (totalCases ?? cases.length) : localCases.length}</div>
        </div>
        <div className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
          <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Статус</div>
          <div className="mt-2 text-[13px] text-[var(--fg-2)]">{state === 'loading' ? 'Загрузка' : state === 'error' ? error : 'Готово'}</div>
        </div>
      </div>

      <section className="overflow-hidden rounded-takt border border-[var(--line)] bg-[var(--bg-1)]">
        {results.length === 0 ? (
          <div className="p-4 text-[13px] text-[var(--fg-2)]">Ничего не найдено по текущим фильтрам.</div>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {results.map((item) => (
              <article key={`${item.kind}:${item.id}`} className="grid gap-3 p-3 lg:grid-cols-[92px_minmax(0,1fr)_220px]">
                <div>
                  <Chip active={item.kind === 'event'}>{item.kind === 'event' ? 'event' : 'case'}</Chip>
                  <div className="mt-2 font-mono text-[11px] text-[var(--fg-3)]">{item.at ? new Date(item.at).toLocaleString('ru-RU') : item.id}</div>
                </div>
                <div className="min-w-0">
                  <h2 className="truncate text-[14px] font-medium text-[var(--fg-1)]">{item.title}</h2>
                  <p className="mt-1 truncate text-[12px] text-[var(--fg-2)]">{item.subtitle || item.id}</p>
                  {item.kind === 'event' ? (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {entityPairs(item.event).slice(0, 6).map(([key, value]) => (
                        <button
                          key={`${item.id}:${key}:${value}`}
                          type="button"
                          onClick={() => setEntityFilter(key, value)}
                          className="rounded-takt border border-[var(--line)] px-2 py-0.5 font-mono text-[11px] text-[var(--fg-2)] hover:bg-[var(--bg-2)] takt-focus-ring"
                        >
                          {key}={value}
                        </button>
                      ))}
                    </div>
                  ) : null}
                </div>
                <div className="flex flex-wrap items-start justify-end gap-2">
                  {item.kind === 'case' ? (
                    <Link className="rounded-takt border border-[var(--line)] px-3 py-1.5 text-[13px] text-[var(--fg-1)] hover:bg-[var(--bg-2)] takt-focus-ring" to={`/cases/${encodeURIComponent(item.id)}`}>
                      Открыть кейс
                    </Link>
                  ) : (
                    <>
                      {entityPairs(item.event).find(([key]) => key === 'host_id' || key === 'user_id' || key === 'process_id') ? (
                        <Button
                          variant="ghost"
                          onClick={() => {
                            const pair = entityPairs(item.event).find(([key]) => key === 'host_id' || key === 'user_id' || key === 'process_id')
                            if (pair) {
                              setEntityFilter(pair[0], pair[1])
                            }
                          }}
                        >
                          Карточка сущности
                        </Button>
                      ) : null}
                    </>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
