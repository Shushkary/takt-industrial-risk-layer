import { useEffect, useMemo, useState } from 'react'
import { Boxes, Compass, Network, NotebookPen, Radar } from 'lucide-react'
import { InvestigationGraph, type GraphSelection } from '../components/investigation/InvestigationGraph'
import { InvestigationTimeline } from '../components/investigation/InvestigationTimeline'
import { SourceFusionRibbon } from '../components/investigation/SourceFusionRibbon'
import { EntityCardPanel } from '../components/investigation/EntityCardPanel'
import { FindingsJournal } from '../components/investigation/FindingsJournal'
import { ResponsePackagePanel } from '../components/investigation/ResponsePackagePanel'
import {
  useEntityCard,
  useIncidentQueue,
  useInvestigationMode,
  useSourceCounts,
  useSpreadSearch,
  useWorkspace,
} from '../investigation/useInvestigation'
import type { EntityKind, InvestigationEvent } from '../investigation/types'
import { SOURCE_COLORS, SOURCE_LABELS } from '../investigation/types'

/**
 * Единый рабочий стол расследования (ТЗ п. 5.1, п. 9.1).
 *
 * Один экран закрывает контур: очередь инцидентов, события всех подключённых
 * источников, граф связей и таймлайн, карточка сущности, журнал находок,
 * оценка распространения и пакет для реагирования — без переключения систем.
 */

type RightTab = 'entity' | 'findings' | 'chain' | 'response'

const RISK_COLORS: Record<string, string> = {
  LOW: 'var(--risk-low)',
  MEDIUM: 'var(--risk-mid)',
  HIGH: 'var(--risk-high)',
  CRITICAL: 'var(--risk-crit)',
}

const ENTITY_KINDS: Record<string, EntityKind | null> = {
  host: 'host',
  user: 'user',
  process: 'process',
}

function eventTime(event: InvestigationEvent): number {
  const value = Date.parse(event.observed_at)
  return Number.isNaN(value) ? 0 : value
}

function formatMoment(value: string): string {
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? value : new Date(parsed).toISOString().replace('T', ' ').slice(0, 19)
}

export function InvestigationDesk() {
  const mode = useInvestigationMode()
  const queue = useIncidentQueue(mode)
  const [caseId, setCaseId] = useState<string | null>(null)

  useEffect(() => {
    if (!caseId && queue.items.length > 0) {
      setCaseId(queue.items[0].case_id)
    }
  }, [caseId, queue.items])

  const { workspace, loading, error, addFinding, confirmCase } = useWorkspace(mode, caseId)
  const counts = useSourceCounts(workspace)
  const spread = useSpreadSearch(mode)

  const [cursor, setCursor] = useState(0)
  const [selectedNode, setSelectedNode] = useState<GraphSelection>(null)
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null)
  const [sourceFilter, setSourceFilter] = useState<string | null>(null)
  const [tab, setTab] = useState<RightTab>('entity')

  const events = useMemo(
    () => [...(workspace?.events ?? [])].sort((a, b) => eventTime(a) - eventTime(b)),
    [workspace],
  )

  useEffect(() => {
    if (events.length > 0) {
      setCursor(eventTime(events[events.length - 1]))
      setSelectedNode(null)
      setSelectedEventId(null)
      spread.reset()
    }
    // spread.reset стабилен по useCallback; перезапуск нужен только при смене набора событий
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events])

  const activeEventIds = useMemo(
    () => new Set(events.filter((event) => eventTime(event) <= cursor).map((event) => event.event_id)),
    [events, cursor],
  )

  const entityKind = selectedNode ? ENTITY_KINDS[selectedNode.type] ?? null : null
  const entity = useEntityCard(mode, entityKind, selectedNode?.value ?? null)

  useEffect(() => {
    if (selectedNode && entityKind) {
      setTab('entity')
    }
  }, [selectedNode, entityKind])

  const visibleEvents = useMemo(
    () => events.filter((event) => (sourceFilter ? event.source === sourceFilter : true)),
    [events, sourceFilter],
  )

  const selectedEvent = events.find((event) => event.event_id === selectedEventId) ?? null
  const caseRisk = workspace?.case.risk_class ?? 'LOW'

  return (
    <div className="flex flex-col gap-3">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-[16px] text-[var(--fg-1)]">Рабочий стол расследования</h1>
          <p className="max-w-[70ch] text-[12px] text-[var(--fg-2)]">
            Инцидент, события всех подключённых классов источников, связи, хронология и находки — в одном окне,
            без переключения между консолями продуктов.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className="rounded-takt border px-2 py-1 text-[11px]"
            style={{ borderColor: mode === 'api' ? 'var(--teal-2)' : 'var(--amber-2)', color: 'var(--fg-1)' }}
          >
            {mode === 'api' ? 'живой API' : 'демонстрационный набор'}
          </span>
          {workspace ? (
            <span
              className="rounded-takt border px-2 py-1 text-[11px]"
              style={{ borderColor: RISK_COLORS[caseRisk] ?? 'var(--line)', color: 'var(--fg-1)' }}
            >
              риск {caseRisk} · {(workspace.case.risk_score ?? 0).toFixed(2)}
            </span>
          ) : null}
        </div>
      </header>

      {error ? (
        <div className="rounded-takt border border-[var(--risk-high)] px-3 py-2 text-[12px] text-[var(--fg-1)]">
          {error}
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[210px_minmax(0,1fr)_330px]">
        <aside className="takt-card flex max-h-[640px] flex-col overflow-hidden">
          <div className="border-b border-[var(--line)] px-2.5 py-2 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
            Очередь инцидентов
          </div>
          <ul className="flex-1 overflow-y-auto p-1.5">
            {queue.loading ? <li className="investigation-skeleton m-1 h-14 rounded-takt" /> : null}
            {queue.items.map((item) => {
              const active = item.case_id === caseId
              return (
                <li key={item.case_id}>
                  <button
                    type="button"
                    onClick={() => setCaseId(item.case_id)}
                    className={`takt-focus-ring mb-1 w-full rounded-takt border px-2 py-1.5 text-left transition-colors duration-takt ${
                      active
                        ? 'border-[var(--teal-2)] bg-[var(--bg-2)]'
                        : 'border-transparent hover:border-[var(--line-strong)]'
                    }`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span
                        className="h-1.5 w-1.5 shrink-0 rounded-full"
                        style={{ backgroundColor: RISK_COLORS[item.risk_class] ?? 'var(--fg-3)' }}
                      />
                      <span className="truncate text-[12px] text-[var(--fg-1)]">{item.title}</span>
                    </div>
                    <div className="mt-0.5 flex items-center justify-between font-mono text-[10px] text-[var(--fg-3)]">
                      <span>{item.case_id.slice(0, 12)}</span>
                      <span>{item.risk_score.toFixed(2)}</span>
                    </div>
                  </button>
                </li>
              )
            })}
            {!queue.loading && queue.items.length === 0 ? (
              <li className="px-2 py-3 text-[12px] text-[var(--fg-3)]">Очередь пуста</li>
            ) : null}
          </ul>
        </aside>

        <section className="flex min-w-0 flex-col gap-3">
          {workspace ? (
            <SourceFusionRibbon
              countsBySource={counts}
              caseTitle={workspace.case.title ?? workspace.case.case_id}
              riskClass={caseRisk}
              activeSource={sourceFilter}
              onSelectSource={setSourceFilter}
            />
          ) : null}

          <div className="takt-card p-3">
            <div className="mb-2 flex items-center gap-2">
              <Network size={14} className="text-[var(--teal-1)]" />
              <span className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Граф связей</span>
              <span className="ml-auto text-[11px] text-[var(--fg-3)]">
                нажмите на узел — откроется карточка сущности
              </span>
            </div>
            <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-[var(--fg-3)]">
              {(
                [
                  ['host', 'узел', '#38bdf8'],
                  ['user', 'пользователь', '#a78bfa'],
                  ['process', 'процесс', '#2dd4bf'],
                  ['address', 'адрес', '#94a3b8'],
                  ['hash', 'хеш / файл', '#f59e0b'],
                  ['domain', 'домен', '#fb7185'],
                ] as Array<[string, string, string]>
              ).map(([key, label, color]) => (
                <span key={key} className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                  {label}
                </span>
              ))}
            </div>
            {loading ? (
              <div className="investigation-skeleton h-[420px] rounded-takt" />
            ) : (
              <InvestigationGraph
                nodes={workspace?.graph.nodes ?? []}
                edges={workspace?.graph.edges ?? []}
                activeEventIds={activeEventIds}
                selectedId={selectedNode?.id ?? null}
                onSelect={setSelectedNode}
              />
            )}
          </div>

          <div className="takt-card p-3">
            <div className="mb-2 flex items-center gap-2">
              <Compass size={14} className="text-[var(--teal-1)]" />
              <span className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
                Хронология расследования
              </span>
            </div>
            <InvestigationTimeline
              events={events}
              cursor={cursor}
              onCursorChange={setCursor}
              selectedEventId={selectedEventId}
              onSelectEvent={setSelectedEventId}
            />
          </div>

          <div className="takt-card">
            <div className="flex items-center gap-2 border-b border-[var(--line)] px-3 py-2">
              <Boxes size={14} className="text-[var(--teal-1)]" />
              <span className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
                События кейса ({visibleEvents.length})
              </span>
              {sourceFilter ? (
                <button
                  type="button"
                  onClick={() => setSourceFilter(null)}
                  className="takt-focus-ring ml-auto rounded-takt border border-[var(--line)] px-2 py-0.5 text-[11px] text-[var(--fg-2)]"
                >
                  сбросить фильтр «{SOURCE_LABELS[sourceFilter] ?? sourceFilter}»
                </button>
              ) : null}
            </div>
            <div className="max-h-[260px] overflow-y-auto">
              <table className="w-full text-left text-[12px]">
                <thead className="sticky top-0 bg-[var(--bg-1)] text-[11px] text-[var(--fg-3)]">
                  <tr>
                    <th className="px-3 py-1.5 font-normal">Время</th>
                    <th className="px-3 py-1.5 font-normal">Источник</th>
                    <th className="px-3 py-1.5 font-normal">Операция</th>
                    <th className="px-3 py-1.5 font-normal">Узел</th>
                    <th className="px-3 py-1.5 font-normal">Артефакты</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleEvents.map((event) => {
                    const played = activeEventIds.has(event.event_id)
                    return (
                      <tr
                        key={event.event_id}
                        onClick={() => setSelectedEventId(event.event_id === selectedEventId ? null : event.event_id)}
                        className={`cursor-pointer border-t border-[var(--line)] transition-colors duration-takt ${
                          event.event_id === selectedEventId ? 'bg-[var(--bg-2)]' : 'hover:bg-[var(--bg-2)]'
                        }`}
                        style={{ opacity: played ? 1 : 0.45 }}
                      >
                        <td className="px-3 py-1.5 font-mono text-[11px] text-[var(--fg-2)]">
                          {formatMoment(event.observed_at).slice(11)}
                        </td>
                        <td className="px-3 py-1.5">
                          <span style={{ color: SOURCE_COLORS[event.source] ?? 'var(--fg-2)' }}>
                            {SOURCE_LABELS[event.source] ?? event.source}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 font-mono text-[11px] text-[var(--fg-1)]">{event.operation}</td>
                        <td className="px-3 py-1.5 font-mono text-[11px] text-[var(--fg-2)]">
                          {event.entities?.host_id ?? '—'}
                        </td>
                        <td className="px-3 py-1.5 text-[11px] text-[var(--fg-2)]">
                          {event.artifacts.length > 0
                            ? event.artifacts.map((item) => item.type).join(', ')
                            : '—'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <aside className="takt-card flex max-h-[860px] min-w-0 flex-col overflow-hidden">
          <div className="flex shrink-0 border-b border-[var(--line)]">
            {(
              [
                ['entity', 'Сущность', Radar],
                ['findings', 'Находки', NotebookPen],
                ['chain', 'Цепочка', Compass],
                ['response', 'Пакет', Boxes],
              ] as Array<[RightTab, string, typeof Radar]>
            ).map(([key, label, Icon]) => (
              <button
                key={key}
                type="button"
                onClick={() => setTab(key)}
                className={`takt-focus-ring flex flex-1 items-center justify-center gap-1 px-1.5 py-2 text-[11px] transition-colors duration-takt ${
                  tab === key
                    ? 'border-b-2 border-[var(--teal-1)] text-[var(--fg-1)]'
                    : 'border-b-2 border-transparent text-[var(--fg-3)] hover:text-[var(--fg-2)]'
                }`}
              >
                <Icon size={12} />
                {label}
              </button>
            ))}
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto p-3">
            {tab === 'entity' ? (
              <div className="flex flex-col gap-3">
                <EntityCardPanel
                  card={entity.card}
                  loading={entity.loading}
                  error={entity.error}
                  emptyHint="Выберите узел, пользователя или процесс на графе, чтобы увидеть историчность и окружение."
                />
                {selectedEvent ? (
                  <div className="rounded-takt border border-[var(--line)] p-2.5">
                    <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
                      Выбранное событие
                    </div>
                    <div className="font-mono text-[11px] text-[var(--fg-1)]">{selectedEvent.event_id}</div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {selectedEvent.artifacts.map((artifact) => (
                        <button
                          key={`${artifact.type}:${artifact.value}`}
                          type="button"
                          onClick={() => {
                            spread.search(artifact.type, artifact.value)
                            setTab('chain')
                          }}
                          className="takt-focus-ring rounded-takt border border-[var(--line-strong)] px-1.5 py-0.5 text-[10px] text-[var(--fg-2)] transition-colors duration-takt hover:border-[var(--teal-2)] hover:text-[var(--fg-1)]"
                          title="Найти этот артефакт во всех источниках"
                        >
                          {artifact.type}: {artifact.value.slice(0, 18)}
                          {artifact.value.length > 18 ? '…' : ''}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            ) : null}

            {tab === 'findings' ? (
              <FindingsJournal
                findings={workspace?.findings ?? []}
                selectedEventIds={selectedEventId ? [selectedEventId] : []}
                onAdd={addFinding}
                localOnly={mode === 'demo'}
              />
            ) : null}

            {tab === 'chain' ? (
              <div className="flex flex-col gap-3">
                <div>
                  <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
                    Реконструкция цепочки
                  </div>
                  <div className="text-[12px] text-[var(--fg-2)]">
                    Точка входа:{' '}
                    <span className="font-mono text-[var(--fg-1)]">
                      {workspace?.attack_chain.entry_point || '—'}
                    </span>
                  </div>
                  <ol className="mt-2 flex flex-col gap-1">
                    {(workspace?.attack_chain.steps ?? []).map((step, index) => (
                      <li
                        key={`${step.event_id}-${step.order}`}
                        className="investigation-fade rounded-takt border border-[var(--line)] px-2 py-1.5 text-[11px]"
                        style={{ animationDelay: `${index * 40}ms` }}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[var(--fg-1)]">{step.operation}</span>
                          <span style={{ color: SOURCE_COLORS[step.source] ?? 'var(--fg-3)' }}>
                            {SOURCE_LABELS[step.source] ?? step.source}
                          </span>
                        </div>
                        <div className="font-mono text-[10px] text-[var(--fg-3)]">
                          {step.from_entity || '—'} → {step.to_entity || '—'}
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>

                <div>
                  <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
                    Оценка распространения
                  </div>
                  {spread.query ? (
                    <div className="mb-1 break-all font-mono text-[10px] text-[var(--fg-3)]">
                      {spread.query.type}: {spread.query.value}
                    </div>
                  ) : (
                    <div className="text-[11px] text-[var(--fg-3)]">
                      Выберите артефакт на вкладке «Сущность», чтобы найти его на других узлах.
                    </div>
                  )}
                  {spread.busy ? <div className="investigation-skeleton h-10 rounded-takt" /> : null}
                  {spread.error ? (
                    <div className="text-[11px] text-[var(--risk-high)]">{spread.error}</div>
                  ) : null}
                  {spread.results ? (
                    <ul className="mt-1 flex flex-col gap-1">
                      {[...new Set(spread.results.map((item) => item.entities?.host_id ?? '—'))].map((host) => (
                        <li
                          key={host}
                          className="rounded-takt border border-[var(--line)] px-2 py-1 font-mono text-[11px] text-[var(--fg-1)]"
                        >
                          {host}
                        </li>
                      ))}
                      <li className="text-[11px] text-[var(--fg-3)]">
                        всего событий: {spread.results.length}
                      </li>
                    </ul>
                  ) : null}
                </div>
              </div>
            ) : null}

            {tab === 'response' ? (
              <ResponsePackagePanel
                artifacts={workspace?.artifacts ?? []}
                caseId={workspace?.case.case_id ?? 'unknown'}
                onConfirm={confirmCase}
                confirmed={workspace?.case.status === 'CONFIRMED'}
                localOnly={mode === 'demo'}
              />
            ) : null}
          </div>
        </aside>
      </div>
    </div>
  )
}
