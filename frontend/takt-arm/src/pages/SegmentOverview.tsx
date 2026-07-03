import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { MetricTile } from '../components/ui/MetricTile'
import { RiskBadge } from '../components/ui/RiskBadge'
import { useUiStore } from '../store/uiStore'
import { formatPercent, formatRisk } from '../app/format'
import { useCaseRows } from '../app/useCaseRows'
import {
  fetchDataQualityReport,
  fetchHealth,
  taktApiConfigured,
  type DataQualityReportResponse,
  type HealthResponse,
} from '../app/taktApi'
import {
  demoIncidents,
  demoScenarios,
  emulateIncidentRisk,
  selectDemoIncidents,
  selectDemoTopology,
  useDemoStore,
  type DemoRiskControls,
  type DemoScenarioId,
  type DemoSegmentMode,
  type DemoShiftPhase,
} from '../demo'

function numberFromStats(stats: Record<string, unknown> | null, key: string): number | null {
  const value = stats?.[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function countFromMap(stats: Record<string, unknown> | null, key: string, names: string[]): number | null {
  const value = stats?.[key]
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null
  }
  const record = value as Record<string, unknown>
  return names.reduce((sum, name) => {
    const count = record[name]
    return sum + (typeof count === 'number' && Number.isFinite(count) ? count : 0)
  }, 0)
}

function stringField(record: Record<string, unknown> | null, key: string): string | null {
  const value = record?.[key]
  if (typeof value === 'string' && value.trim()) {
    return value
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false'
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value)
  }
  return null
}

const apiStatusLabels: Record<'local' | 'loading' | 'loaded' | 'error', string> = {
  local: 'локальный режим',
  loading: 'загружается',
  loaded: 'загружено',
  error: 'ошибка API',
}

const modeLabels = {
  NORMAL: 'Штатный',
  DEGRADED: 'Деградация',
  'AIR-GAP': 'Изоляция',
  STORM: 'Пик нагрузки',
} as const

function SegmentMap({
  scenarioId,
  segmentMode,
  shiftPhase,
  riskControls,
}: {
  scenarioId: DemoScenarioId
  segmentMode: DemoSegmentMode
  shiftPhase: DemoShiftPhase
  riskControls: DemoRiskControls
}) {
  const { links: visibleLinks, nodes: visibleNodes } = selectDemoTopology({
    scenarioId,
    segmentMode,
    shiftPhase,
    riskControls,
    rangeDays: 3,
    linkCategories: [],
  })
  const nodeById = new Map(visibleNodes.map((node) => [node.id, node]))

  return (
    <div
      className="relative h-[420px] overflow-hidden rounded-takt border border-[var(--line)] bg-[var(--bg-0)]"
      role="img"
      aria-label="Карта связей выбранного сегмента теплоэнергетики"
    >
      <svg className="h-full w-full" viewBox="0 0 100 100">
        {visibleLinks.map((link) => {
          const from = nodeById.get(link.from)
          const to = nodeById.get(link.to)
          if (!from || !to) return null
          return (
            <line
              key={link.id}
              x1={from.x}
              y1={from.y}
              x2={to.x}
              y2={to.y}
              stroke={link.state === 'warning' ? 'var(--amber-1)' : 'var(--line-strong)'}
              strokeWidth={link.state === 'warning' ? '0.8' : '0.5'}
              strokeDasharray={link.state === 'warning' ? '2 1.5' : undefined}
            />
          )
        })}
        {visibleNodes.map(({ id, label, x, y, state }) => (
          <g key={id} transform={`translate(${x} ${y})`}>
            <circle r="4" fill="var(--bg-2)" stroke={state === 'normal' ? 'var(--teal-1)' : 'var(--amber-1)'} strokeWidth="0.8" />
            <text y="9" textAnchor="middle" fill="var(--fg-2)" fontSize="2.8" fontFamily="monospace">
              {label}
            </text>
          </g>
        ))}
      </svg>
    </div>
  )
}

export function SegmentOverview() {
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [dataQuality, setDataQuality] = useState<DataQualityReportResponse | null>(null)
  const [apiStatus, setApiStatus] = useState<'local' | 'loading' | 'loaded' | 'error'>(
    taktApiConfigured() ? 'loading' : 'local',
  )
  const { segmentMode, shiftPhase, partialObservability } = useUiStore()
  const { scenarioId, riskControls } = useDemoStore()
  const activeScenario = demoScenarios.find((scenario) => scenario.id === scenarioId) ?? demoScenarios[0]
  const activeScenarioTitle = activeScenario?.title ?? 'Сценарий не выбран'
  const currentIncidents = selectDemoIncidents({ scenarioId, segmentMode, shiftPhase, riskControls })
  const scenarioIncidents = demoIncidents
    .filter((incident) => incident.scenarioId === scenarioId)
    .map((incident) => ({ ...incident, risk: emulateIncidentRisk(incident, riskControls) }))
  const demoSourceRows = currentIncidents.length > 0 ? currentIncidents : scenarioIncidents
  const caseRows = useCaseRows({
    demoRows: demoSourceRows,
    scenarioId,
    segmentMode,
    shiftPhase,
    limit: 5,
  })
  const topIncidents = caseRows.rows
    .slice()
    .sort((left, right) => right.risk - left.risk)
  const fallbackByScenario = caseRows.mode === 'local-demo' && currentIncidents.length === 0
  const overviewTopology = selectDemoTopology({
    scenarioId,
    segmentMode,
    shiftPhase,
    riskControls,
    rangeDays: 3,
    linkCategories: [],
  })
  const rhythmItems = overviewTopology.nodes
    .filter((node) => ['plc', 'sensor', 'gateway', 'cabinet'].includes(node.kind))
    .slice(0, 3)
  const mainRisk = topIncidents[0]?.risk ?? 0
  const apiTotalCases = numberFromStats(caseRows.stats, 'total')
  const apiHighRiskCount = countFromMap(caseRows.stats, 'by_risk_class', ['HIGH', 'CRITICAL'])
  const apiDataSourceCount = countFromMap(caseRows.stats, 'by_last_event_source', ['plc_polling', 'auth_logs', 'network_events', 'service_desk', 'unknown'])
  const isApiMode = caseRows.mode === 'api'
  const healthService = stringField(health, 'service') ?? stringField(health, 'status') ?? stringField(health, 'ok') ?? 'нет данных'
  const healthVersion = stringField(health, 'version') ?? stringField(health, 'app_version') ?? 'нет данных'
  const openCases = numberFromStats(dataQuality, 'open_cases')
  const withoutManualPermit = numberFromStats(dataQuality, 'cases_without_manual_permit')
  const highRiskWithoutDecision = numberFromStats(dataQuality, 'high_risk_without_decision')

  useEffect(() => {
    let cancelled = false
    if (!taktApiConfigured()) {
      setApiStatus('local')
      setHealth(null)
      setDataQuality(null)
      return
    }
    setApiStatus('loading')
    Promise.all([fetchHealth(), fetchDataQualityReport()])
      .then(([healthResponse, qualityResponse]) => {
        if (cancelled) {
          return
        }
        setHealth(healthResponse)
        setDataQuality(qualityResponse)
        setApiStatus('loaded')
      })
      .catch(() => {
        if (!cancelled) {
          setHealth(null)
          setDataQuality(null)
          setApiStatus('error')
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-[20px] font-semibold tracking-tight text-[var(--fg-1)]">Обзор сегмента</h1>
        <p className="mt-1 max-w-[72ch] text-[13px] text-[var(--fg-2)]">
          Главный экран дежурного: режим площадки, карта связей, ритм опроса, топ активных инцидентов и качество данных.
        </p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile label="Режим" value={modeLabels[segmentMode]} hint="Состояние источников и расчёта риска" />
        <MetricTile
          label={isApiMode ? 'Кейсы API' : 'Сценарий'}
          value={isApiMode ? (apiTotalCases ?? topIncidents.length) : activeScenarioTitle}
          hint={isApiMode ? '/cases/stats total' : fallbackByScenario ? 'Показаны события сценария' : 'Режим и фаза совпали'}
        />
        <MetricTile
          label={isApiMode ? 'Источники API' : 'Частичная наблюдаемость'}
          value={isApiMode ? (apiDataSourceCount ?? 0) : formatPercent(partialObservability * 100)}
          hint={isApiMode ? '/cases/stats by_last_event_source' : 'При деградации часть источников недоступна, риск пересчитывается'}
        />
        {isApiMode ? <MetricTile label="HIGH/CRITICAL" value={apiHighRiskCount ?? 0} hint="/cases/stats by_risk_class" /> : <RiskBadge value={mainRisk} />}
      </div>
      {isApiMode ? (
        <section className="grid gap-3 md:grid-cols-4">
          <article className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
            <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">API health</h2>
            <p className="mt-2 font-mono text-[12px] text-[var(--fg-2)]">
              {apiStatus === 'loaded' ? `/health ${healthService}` : apiStatusLabels[apiStatus]}
            </p>
            <p className="mt-1 font-mono text-[12px] text-[var(--fg-3)]">версия {healthVersion}</p>
          </article>
          <MetricTile label="Открытые кейсы" value={openCases ?? 'нет данных'} hint="/compliance/data-quality-report open_cases" />
          <MetricTile
            label="Без ручного наряда"
            value={withoutManualPermit ?? 'нет данных'}
            hint="/compliance/data-quality-report cases_without_manual_permit"
          />
          <MetricTile
            label="HIGH без решения"
            value={highRiskWithoutDecision ?? 'нет данных'}
            hint="/compliance/data-quality-report high_risk_without_decision"
          />
        </section>
      ) : null}
      <div className="grid gap-4 xl:grid-cols-[280px_minmax(0,1fr)_320px]">
        <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-4">
          <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Модуль ритма</h2>
          {(rhythmItems.length > 0 ? rhythmItems.map((node) => node.label) : [activeScenarioTitle]).map((name, index) => (
            <div key={name} className="mt-3 grid grid-cols-[64px_1fr_54px] items-center gap-2 font-mono text-[12px]">
              <span>{name}</span>
              <span className="h-1.5 rounded-takt bg-[var(--amber-1)]" style={{ width: `${74 - index * 12}%` }} />
              <b>{formatRisk(4.51 + index * 0.06)}</b>
            </div>
          ))}
          <p className="mt-4 border-l-2 border-[var(--amber-1)] bg-[rgba(245,158,11,0.08)] p-2 text-[12px] text-[var(--fg-2)]">
            {rhythmItems[0]?.label ?? activeScenarioTitle} входит в зону контроля стабильности интервала опроса.
          </p>
        </section>
        <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-4">
          <h2 className="mb-3 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Карта связей сегмента</h2>
          <SegmentMap scenarioId={scenarioId} segmentMode={segmentMode} shiftPhase={shiftPhase} riskControls={riskControls} />
        </section>
        <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-4">
          <h2 className="mb-3 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Топ-5 активных инцидентов</h2>
          <div className="flex flex-col gap-2">
            {topIncidents.slice(0, 5).map((incident) => (
              <article key={incident.id} className="grid grid-cols-[1fr_92px] gap-2 border border-[var(--line)] bg-[var(--bg-0)] p-2">
                <div>
                  <b className="block font-mono text-[12px]">{incident.node}</b>
                  <span className="text-[12px] text-[var(--fg-2)]">{incident.summary}</span>
                  <Link
                    to={`/cases/${encodeURIComponent(incident.id)}`}
                    className="mt-2 inline-flex text-[12px] text-[var(--teal-1)] hover:underline takt-focus-ring"
                  >
                    Открыть карточку
                  </Link>
                </div>
                <RiskBadge value={incident.risk} />
              </article>
            ))}
            {topIncidents.length === 0 ? (
              <p className="text-[12px] text-[var(--fg-3)]">Для выбранного сценария пока нет событий.</p>
            ) : fallbackByScenario ? (
              <p className="text-[12px] text-[var(--fg-3)]">
                Для выбранного режима и фазы событий нет, показаны инциденты сценария.
              </p>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  )
}




