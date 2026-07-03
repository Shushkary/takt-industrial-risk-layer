import { useEffect, useMemo, useState, type CSSProperties } from 'react'
import {
  demoScenarios,
  emulateRiskSummary,
  selectDemoTopology,
  useDemoStore,
  type DemoLinkCategory,
  type DemoLink,
  type DemoNode,
} from '../demo'
import { fetchTopologyDemoGraph, taktApiConfigured, type TopologyDemoGraphResponse } from '../app/taktApi'
import { formatRisk } from '../app/format'
import { useUiStore } from '../store/uiStore'

type RangeLabel = '1 день' | '3 дня' | '1 неделя' | '1 месяц'
type ObjectFilter = 'Обходы инженерной станции' | 'ПЛК' | 'Шлюзы'

const timeRanges: Array<{ label: RangeLabel; days: number }> = [
  { label: '3 дня', days: 3 },
  { label: '1 день', days: 1 },
  { label: '1 неделя', days: 7 },
  { label: '1 месяц', days: 30 },
]

const objectFilters: ObjectFilter[] = ['Обходы инженерной станции', 'ПЛК', 'Шлюзы']

const filterToCategory: Record<ObjectFilter, DemoLinkCategory> = {
  'Обходы инженерной станции': 'engineering_bypass',
  ПЛК: 'plc',
  Шлюзы: 'gateway',
}

const kindLabels: Record<DemoNode['kind'], string> = {
  dispatch: 'диспетчерская',
  engineering: 'АРМ',
  server: 'сервер',
  plc: 'ПЛК',
  gateway: 'шлюз',
  archive: 'архив',
  sensor: 'датчики',
  cabinet: 'шкаф телемеханики',
}

function clampRisk(value: number) {
  return Math.max(0, Math.min(0.99, value))
}

function getRiskColor(value: number) {
  if (value >= 0.9) return 'var(--risk-crit)'
  if (value >= 0.7) return 'var(--risk-high)'
  if (value >= 0.4) return 'var(--risk-mid)'
  return 'var(--risk-low)'
}

function getRiskLabel(value: number) {
  if (value >= 0.9) return 'критичный'
  if (value >= 0.7) return 'высокий'
  if (value >= 0.4) return 'средний'
  return 'низкий'
}

function apiNodeKind(id: string, topology: TopologyDemoGraphResponse): DemoNode['kind'] {
  if (id === topology.jump_host) return 'engineering'
  if (topology.plc_hosts.includes(id)) return 'plc'
  if (id.toLocaleLowerCase('ru-RU').includes('gateway')) return 'gateway'
  if (id.toLocaleLowerCase('ru-RU').includes('archive')) return 'archive'
  return 'server'
}

function apiLinkCategory(edge: TopologyDemoGraphResponse['edges'][number], topology: TopologyDemoGraphResponse): DemoLinkCategory {
  if (edge.src === topology.jump_host || edge.dst === topology.jump_host) return 'engineering_bypass'
  if (topology.plc_hosts.includes(edge.src) || topology.plc_hosts.includes(edge.dst)) return 'plc'
  if (edge.kind.toLocaleLowerCase('ru-RU').includes('gateway')) return 'gateway'
  return 'regular'
}

function apiTopologyToVisual(
  topology: TopologyDemoGraphResponse,
  scenarioId: DemoNode['scenarioId'],
): { nodes: DemoNode[]; links: DemoLink[]; selectedLinks: DemoLink[] } {
  const ids = Array.from(new Set([topology.jump_host, ...topology.plc_hosts, ...topology.edges.flatMap((edge) => [edge.src, edge.dst])])).filter(Boolean)
  const radius = 34
  const nodes = ids.map((id, index): DemoNode => {
    const angle = ids.length <= 1 ? 0 : (Math.PI * 2 * index) / ids.length - Math.PI / 2
    const kind = apiNodeKind(id, topology)
    return {
      id,
      label: id,
      kind,
      x: 50 + Math.cos(angle) * radius,
      y: 50 + Math.sin(angle) * radius,
      state: topology.has_jump_bypass_pattern && kind === 'plc' ? 'warning' : 'normal',
      lastSeenDays: 0,
      scenarioId,
      modes: ['NORMAL', 'DEGRADED', 'AIR-GAP', 'STORM'],
      phases: ['WORK', 'NIGHT', 'MAINT'],
    }
  })
  const links = topology.edges.map((edge, index): DemoLink => {
    const category = apiLinkCategory(edge, topology)
    const state = topology.has_jump_bypass_pattern && category === 'engineering_bypass' ? 'warning' : 'normal'
    return {
      id: `api-${index}-${edge.src}-${edge.dst}`,
      label: `${edge.src} -> ${edge.dst}`,
      from: edge.src,
      to: edge.dst,
      state,
      lastSeenDays: 0,
      categories: [category],
      scenarioId,
      detail: `API /topology/demo-graph: ${edge.kind}`,
      modes: ['NORMAL', 'DEGRADED', 'AIR-GAP', 'STORM'],
      phases: ['WORK', 'NIGHT', 'MAINT'],
    }
  })
  return { nodes, links, selectedLinks: links }
}
export function TopologyMap() {
  const { segmentMode, shiftPhase } = useUiStore()
  const { scenarioId, riskControls, setScenarioId, setRiskControl } = useDemoStore()
  const apiConfigured = taktApiConfigured()
  const [activeRange, setActiveRange] = useState<RangeLabel>('3 дня')
  const [activeFilters, setActiveFilters] = useState<ObjectFilter[]>(['Обходы инженерной станции'])
  const rangeDays = timeRanges.find((range) => range.label === activeRange)?.days ?? 3
  const linkCategories = useMemo(() => activeFilters.map((filter) => filterToCategory[filter]), [activeFilters])
  const activeScenario = demoScenarios.find((scenario) => scenario.id === scenarioId) ?? demoScenarios[0]
  const riskSummary = emulateRiskSummary(riskControls)
  const [apiTopology, setApiTopology] = useState<TopologyDemoGraphResponse | null>(null)
  const [apiTopologyState, setApiTopologyState] = useState<'local' | 'loading' | 'loaded' | 'error'>(
    apiConfigured ? 'loading' : 'local',
  )
  const localDemoControlsDisabled = apiConfigured

  useEffect(() => {
    let cancelled = false
    if (!apiConfigured) {
      setApiTopology(null)
      setApiTopologyState('local')
      return
    }
    setApiTopologyState('loading')
    fetchTopologyDemoGraph()
      .then((topology) => {
        if (cancelled) {
          return
        }
        setApiTopology(topology)
        setApiTopologyState(topology ? 'loaded' : 'local')
      })
      .catch(() => {
        if (!cancelled) {
          setApiTopology(null)
          setApiTopologyState('error')
        }
      })
    return () => {
      cancelled = true
    }
  }, [apiConfigured])

  const { visibleLinks, visibleNodes, selectedLinks } = useMemo(() => {
    if (apiTopology) {
      const topology = apiTopologyToVisual(apiTopology, scenarioId)
      return { visibleLinks: topology.links, visibleNodes: topology.nodes, selectedLinks: topology.selectedLinks }
    }
    const topology = selectDemoTopology({
      scenarioId,
      segmentMode,
      shiftPhase,
      riskControls,
      rangeDays,
      linkCategories,
    })
    return { visibleLinks: topology.links, visibleNodes: topology.nodes, selectedLinks: topology.selectedLinks }
  }, [apiTopology, linkCategories, rangeDays, riskControls, scenarioId, segmentMode, shiftPhase])

  const nodeById = useMemo(() => new Map(visibleNodes.map((node) => [node.id, node])), [visibleNodes])
  const warningCount = visibleLinks.filter((link) => link.state !== 'normal').length
  const isApiTopology = apiTopology !== null
  const linkRiskScore = useMemo(
    () => (link: DemoLink) => {
      const stateBase = link.state === 'critical' ? 0.78 : link.state === 'warning' ? 0.52 : 0.18
      if (isApiTopology) {
        return clampRisk(stateBase)
      }
      const engineeringFactor = link.categories.includes('engineering_bypass')
        ? (riskControls.engineeringAccess / 100) * 0.22
        : 0
      const plcFactor = link.categories.includes('plc') ? (riskControls.pollingInstability / 100) * 0.18 : 0
      const gatewayFactor = link.categories.includes('gateway') ? (riskControls.telemetryFreshnessLoss / 100) * 0.14 : 0
      const workOrderFactor = link.state !== 'normal' ? (riskControls.missingWorkOrder / 100) * 0.16 : 0

      return clampRisk(stateBase + engineeringFactor + plcFactor + gatewayFactor + workOrderFactor)
    },
    [isApiTopology, riskControls],
  )
  const linksWithRisk = useMemo(
    () => visibleLinks.map((link) => ({ link, risk: linkRiskScore(link) })),
    [linkRiskScore, visibleLinks],
  )
  const riskByLinkId = useMemo(
    () => new Map(linksWithRisk.map(({ link, risk }) => [link.id, risk])),
    [linksWithRisk],
  )
  const highRiskCount = linksWithRisk.filter(({ risk }) => risk >= 0.7).length
  const maxLinkRisk = linksWithRisk.reduce((max, { risk }) => Math.max(max, risk), 0)

  function toggleFilter(filter: ObjectFilter) {
    setActiveFilters((current) =>
      current.includes(filter) ? current.filter((item) => item !== filter) : [...current, filter],
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">Карта сегмента</h1>
        <p className="mt-1 max-w-[72ch] text-[13px] text-[var(--fg-2)]">
          Реалистичный демо-сегмент теплоэнергетики: подключение из шкафа телемеханики к контроллерам котельной, шлюзам АСУ ТП и архиву телеметрии.
        </p>
      </div>

      <div className="text-[12px] text-[var(--fg-3)]">
        Выборка учитывает режим сегмента и фазу смены из верхней панели. Режим меняет состав наблюдаемой топологии,
        а ползунки пересчитывают риск уже показанных связей без активного управления оборудованием.
        {linkCategories.length > 0 && selectedLinks.length === 0
          ? ' По выбранному фильтру отклонений нет, показана базовая топология объекта.'
          : ''}
      </div>

      <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
        <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Сценарий работы</h2>
        <div className="mt-2 flex flex-wrap gap-2">
          {demoScenarios.map((scenario) => (
            <button
              key={scenario.id}
              type="button"
              onClick={() => setScenarioId(scenario.id)}
              disabled={localDemoControlsDisabled}
              className={`rounded-takt border px-3 py-2 text-[12px] takt-focus-ring ${
                scenarioId === scenario.id
                  ? 'border-[var(--teal-1)] bg-[var(--teal-3)] text-[var(--fg-1)]'
                  : 'border-[var(--line)] bg-[var(--bg-2)] text-[var(--fg-2)] hover:border-[var(--line-strong)]'
              }`}
            >
              {scenario.title}
            </button>
          ))}
        </div>
        <p className="mt-2 text-[12px] text-[var(--fg-2)]">
          {localDemoControlsDisabled
            ? 'Сценарии отключены в API-режиме; рабочая топология берётся из /topology/demo-graph.'
            : `${activeScenario.facility} · ${activeScenario.connectionPoint}`}
        </p>
      </section>

      <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
        <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Эмулятор типичных рисков</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {riskSummary.map((item) => (
            <label key={item.key} className="text-[12px] text-[var(--fg-2)]">
              <span className="flex items-center justify-between gap-2">
                <span>{item.label}</span>
                <span className="font-mono text-[var(--fg-1)]">{item.value}%</span>
              </span>
              <input
                type="range"
                min="0"
                max="100"
                step="5"
                value={item.value}
                disabled={localDemoControlsDisabled}
                onChange={(event) => setRiskControl(item.key, Number(event.target.value))}
                className="mt-2 w-full accent-[var(--teal-1)]"
              />
            </label>
          ))}
        </div>
        <p className="mt-3 text-[12px] text-[var(--fg-3)]">
          {localDemoControlsDisabled
            ? 'Эмулятор типичных рисков отключён в API-режиме и не влияет на рабочий backend-граф.'
            : 'Доступ инженера влияет на обходы инженерной станции, нестабильность опроса - на связи ПЛК, свежесть телеметрии - на шлюзы и архив, отсутствие наряда усиливает риск отклонений без подтверждённой заявки.'}
        </p>
      </section>

      <div className="flex flex-wrap gap-2">
        {timeRanges.map(({ label }) => (
          <button
            key={label}
            type="button"
            onClick={() => setActiveRange(label)}
            disabled={localDemoControlsDisabled}
            className={`rounded-takt border px-3 py-2 text-[12px] takt-focus-ring ${
              activeRange === label
                ? 'border-[var(--teal-1)] bg-[var(--teal-3)] text-[var(--fg-1)]'
                : 'border-[var(--line)] bg-[var(--bg-2)] text-[var(--fg-2)] hover:border-[var(--line-strong)]'
            }`}
          >
            {label}
          </button>
        ))}
        {objectFilters.map((label) => (
          <button
            key={label}
            type="button"
            onClick={() => toggleFilter(label)}
            disabled={localDemoControlsDisabled}
            className={`rounded-takt border px-3 py-2 text-[12px] takt-focus-ring ${
              activeFilters.includes(label)
                ? 'border-[var(--amber-1)] bg-[rgba(245,158,11,0.12)] text-[var(--fg-1)]'
                : 'border-[var(--line)] bg-[var(--bg-2)] text-[var(--fg-2)] hover:border-[var(--line-strong)]'
            }`}
          >
            {label}
          </button>
        ))}
      </div>
      {localDemoControlsDisabled ? (
        <p className="text-[12px] text-[var(--fg-3)]">
          Период и тип объекта отключены в API-режиме; рабочая карта отображает backend `/topology/demo-graph` без локальной фильтрации.
        </p>
      ) : null}

      <div className="grid gap-3 md:grid-cols-4">
        <div className="takt-card p-3">
          <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Узлы</div>
          <div className="mt-1 font-mono text-[24px] text-[var(--fg-1)]">{visibleNodes.length}</div>
        </div>
        <div className="takt-card p-3">
          <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Связи</div>
          <div className="mt-1 font-mono text-[24px] text-[var(--fg-1)]">{visibleLinks.length}</div>
        </div>
        <div className="takt-card p-3">
          <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Отклонения</div>
          <div className="mt-1 font-mono text-[24px] text-[var(--amber-1)]">{warningCount}</div>
        </div>
        <div className="takt-card p-3">
          <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Высокий риск</div>
          <div className="mt-1 flex items-end justify-between gap-2">
            <span className="font-mono text-[24px]" style={{ color: getRiskColor(maxLinkRisk) }}>
              {highRiskCount}
            </span>
            <span className="pb-1 font-mono text-[12px] text-[var(--fg-2)]">макс. {formatRisk(maxLinkRisk)}</span>
          </div>
        </div>
      </div>

      <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Backend topology</h2>
          <span className="font-mono text-[12px] text-[var(--fg-3)]">
            {apiTopologyState === 'loaded'
              ? '/topology/demo-graph'
              : apiTopologyState === 'loading'
                ? 'загружается'
                : apiTopologyState === 'error'
                  ? 'недоступен'
                  : 'локальное демо'}
          </span>
        </div>
        {apiTopology ? (
          <div className="mt-3 grid gap-3 md:grid-cols-[240px_minmax(0,1fr)]">
            <dl className="grid gap-2 text-[12px] text-[var(--fg-2)]">
              <div>
                <dt className="text-[var(--fg-3)]">Переходный сервер</dt>
                <dd className="font-mono text-[var(--fg-1)]">{apiTopology.jump_host}</dd>
              </div>
              <div>
                <dt className="text-[var(--fg-3)]">Узлы ПЛК</dt>
                <dd className="font-mono text-[var(--fg-1)]">{apiTopology.plc_hosts.join(', ') || 'нет данных'}</dd>
              </div>
              <div>
                <dt className="text-[var(--fg-3)]">Паттерн обхода переходного сервера</dt>
                <dd>{apiTopology.has_jump_bypass_pattern ? 'обнаружен' : 'не обнаружен'}</dd>
              </div>
            </dl>
            <ol className="grid gap-2 text-[12px] text-[var(--fg-2)] md:grid-cols-2">
              {apiTopology.edges.map((edge, index) => (
                <li key={`${edge.src}-${edge.dst}-${index}`} className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-2">
                  <span className="font-mono text-[var(--fg-1)]">{edge.src}</span>
                  <span>{' -> '}</span>
                  <span className="font-mono text-[var(--fg-1)]">{edge.dst}</span>
                  <span className="ml-2 text-[var(--fg-3)]">{edge.kind}</span>
                </li>
              ))}
            </ol>
          </div>
        ) : (
          <p className="mt-2 text-[12px] text-[var(--fg-3)]">
            Backend topology не загружена; локальная визуальная карта доступна только для операторского обзора.
          </p>
        )}
      </section>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="min-h-[560px] rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-4">
          <svg className="topology-map h-[520px] w-full bg-[var(--bg-0)]" viewBox="0 0 100 100" role="img" aria-label="Карта связей промышленного сегмента теплоэнергетики">
            <defs>
              <filter id="topology-glow" x="-40%" y="-40%" width="180%" height="180%">
                <feGaussianBlur stdDeviation="1.2" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            {visibleLinks.map((link, index) => {
              const from = nodeById.get(link.from)
              const to = nodeById.get(link.to)
              if (!from || !to) {
                return null
              }
              const risk = riskByLinkId.get(link.id) ?? 0
              const riskColor = getRiskColor(risk)
              const lineStyle = {
                animationDelay: `${index * 140}ms`,
                '--link-risk-color': riskColor,
              } as CSSProperties
              const baseLineStyle = {
                stroke: riskColor,
                strokeWidth: 0.45 + risk * 0.75,
                opacity: 0.42 + risk * 0.5,
              } as CSSProperties
              const flowLineStyle = {
                stroke: riskColor,
                strokeWidth: 0.28 + risk * 0.32,
                opacity: 0.4 + risk * 0.5,
              } as CSSProperties
              return (
                <g key={link.id} className={`topology-link topology-link-${link.state}`} style={lineStyle}>
                  <line
                    className="topology-link-base"
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    style={baseLineStyle}
                  />
                  <line
                    className="topology-link-flow"
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    style={flowLineStyle}
                  />
                </g>
              )
            })}
            {visibleLinks
              .filter((link) => link.state !== 'normal' || (riskByLinkId.get(link.id) ?? 0) >= 0.7)
              .map((link, index) => {
                const from = nodeById.get(link.from)
                const to = nodeById.get(link.to)
                if (!from || !to) {
                  return null
                }
                const risk = riskByLinkId.get(link.id) ?? 0
                return (
                  <circle
                    key={`${link.id}-packet`}
                    className="topology-packet"
                    r="1.2"
                    style={{ animationDelay: `${index * 900}ms`, fill: getRiskColor(risk) }}
                  >
                    <animateMotion dur="4.8s" repeatCount="indefinite" path={`M ${from.x} ${from.y} L ${to.x} ${to.y}`} />
                  </circle>
                )
              })}
            {visibleNodes.map((node) => (
              <g key={node.id} className={`topology-node topology-node-${node.state}`} transform={`translate(${node.x} ${node.y})`}>
                <circle className="topology-node-halo" r={node.kind === 'plc' ? 7 : 6} />
                <circle r={node.kind === 'plc' ? 5 : 4} fill="var(--bg-2)" stroke={node.state === 'normal' ? 'var(--teal-1)' : 'var(--amber-1)'} strokeWidth="0.9" />
                <text y="9" textAnchor="middle" fill="var(--fg-2)" fontSize="2.8" fontFamily="monospace">
                  {node.label}
                </text>
              </g>
            ))}
            <g className="topology-scan" aria-hidden>
              <rect x="0" y="0" width="100" height="100" fill="transparent" />
              <line x1="0" y1="0" x2="100" y2="0" />
            </g>
          </svg>
        </div>

        <aside className="takt-card p-4">
          <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Связи в выборке</h2>
          <div className="mt-3 flex flex-col gap-2">
            {visibleLinks.map((link) => {
              const from = nodeById.get(link.from)
              const to = nodeById.get(link.to)
              const risk = riskByLinkId.get(link.id) ?? 0
              return (
                <article key={link.id} className="border border-[var(--line)] bg-[var(--bg-0)] p-2">
                  <div className="flex items-start justify-between gap-2">
                    <b className="block text-[12px] text-[var(--fg-1)]">{link.label}</b>
                    <span className="font-mono text-[12px]" style={{ color: getRiskColor(risk) }}>
                      {formatRisk(risk)}
                    </span>
                  </div>
                  <p className="mt-1 text-[12px] text-[var(--fg-2)]">{link.detail}</p>
                  <p className="mt-1 text-[11px]" style={{ color: getRiskColor(risk) }}>
                    Риск связи: {getRiskLabel(risk)}
                  </p>
                  <p className="mt-1 text-[11px] text-[var(--fg-3)]">
                    {from ? kindLabels[from.kind] : 'узел'} → {to ? kindLabels[to.kind] : 'узел'} · {activeScenario.title}
                  </p>
                </article>
              )
            })}
            {visibleLinks.length === 0 ? (
              <p className="text-[12px] text-[var(--fg-3)]">Для выбранного режима, фазы и периода связей нет.</p>
            ) : null}
          </div>
        </aside>
      </div>
    </div>
  )
}

