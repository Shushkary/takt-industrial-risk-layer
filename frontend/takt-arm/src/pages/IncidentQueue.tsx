import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { DataTable, type DataTableColumn } from '../components/ui/DataTable'
import { RiskBadge } from '../components/ui/RiskBadge'
import { Chip } from '../components/ui/Chip'
import { Button } from '../components/ui/Button'
import { MetricTile } from '../components/ui/MetricTile'
import { formatRisk } from '../app/format'
import { useCaseRows } from '../app/useCaseRows'
import { fetchComplianceMode, taktApiConfigured, type ComplianceModeResponse } from '../app/taktApi'
import {
  demoIncidents,
  demoScenarios,
  emulateIncidentRisk,
  selectDemoIncidents,
  useDemoStore,
  type DemoIncident,
  type IncidentStatus,
} from '../demo'
import { useUiStore, type SegmentMode, type ShiftPhase } from '../store/uiStore'

const filters: Array<IncidentStatus | 'Все'> = ['Все', 'Разбор', 'Подтверждён', 'Ложное срабатывание', 'Ожидаемое поведение', 'Закрыт']
const apiStatuses = [undefined, 'TRIAGE', 'CONFIRMED', 'FALSE_POSITIVE', 'EXPECTED_BEHAVIOR', 'CLOSED'] as const
const scenarioTitleById = new Map(demoScenarios.map((scenario) => [scenario.id, scenario.title]))
const modeLabels: Record<SegmentMode, string> = {
  NORMAL: 'Штатный',
  DEGRADED: 'Деградация',
  'AIR-GAP': 'Изоляция',
  STORM: 'Пик нагрузки',
}
const phaseLabels: Record<ShiftPhase, string> = {
  WORK: 'Рабочая',
  NIGHT: 'Ночь',
  MAINT: 'Обслуживание',
}

const columns: DataTableColumn<DemoIncident>[] = [
  { id: 'time', header: 'Время', cell: (row) => row.time },
  { id: 'node', header: 'Узел', cell: (row) => row.node },
  { id: 'invariant', header: 'Инвариант', cell: (row) => row.invariant },
  { id: 'risk', header: 'Индекс риска', align: 'right', cell: (row) => <RiskBadge value={row.risk} /> },
  { id: 'phase', header: 'Фаза', cell: (row) => row.phase },
  { id: 'status', header: 'Статус', cell: (row) => row.status },
  { id: 'operator', header: 'Оператор', cell: (row) => row.operator },
  { id: 'scenarioId', header: 'Сценарий', cell: (row) => scenarioTitleById.get(row.scenarioId) ?? row.scenarioId },
]

function complianceEnabled(mode: ComplianceModeResponse | null): boolean {
  return mode?.compliance_enabled === true
}

export function IncidentQueue() {
  const { segmentMode, shiftPhase } = useUiStore()
  const { scenarioId, riskControls } = useDemoStore()
  const [filter, setFilter] = useState<IncidentStatus | 'Все'>('Все')
  const [pageOffset, setPageOffset] = useState(0)
  const [selectedId, setSelectedId] = useState(demoIncidents[0]?.id ?? '')
  const [reportText, setReportText] = useState('')
  const [complianceMode, setComplianceMode] = useState<ComplianceModeResponse | null>(null)
  const pageLimit = 10
  const activeScenario = demoScenarios.find((scenario) => scenario.id === scenarioId) ?? demoScenarios[0]
  const activeScenarioTitle = activeScenario?.title ?? 'Сценарий не выбран'
  const strictRows = useMemo(
    () => selectDemoIncidents({ scenarioId, segmentMode, shiftPhase, riskControls }),
    [riskControls, scenarioId, segmentMode, shiftPhase],
  )
  const scenarioRows = useMemo(
    () =>
      demoIncidents
        .filter((incident) => incident.scenarioId === scenarioId)
        .map((incident) => ({
          ...incident,
          risk: emulateIncidentRisk(incident, riskControls),
        })),
    [riskControls, scenarioId],
  )
  const demoSourceRows = strictRows.length > 0 ? strictRows : scenarioRows
  const apiStatus = apiStatuses[Math.max(0, filters.indexOf(filter))]
  const caseRows = useCaseRows({ demoRows: demoSourceRows, scenarioId, segmentMode, shiftPhase, limit: pageLimit, offset: pageOffset, status: apiStatus })
  const sourceRows = caseRows.rows
  const rows = useMemo(
    () => (caseRows.mode === 'api' ? sourceRows : sourceRows.filter((incident) => filter === filters[0] || incident.status === filter)),
    [caseRows.mode, filter, sourceRows],
  )
  const statusCounts = useMemo(
    () =>
      sourceRows.reduce<Record<string, number>>((counts, incident) => {
        counts[incident.status] = (counts[incident.status] ?? 0) + 1
        return counts
      }, {}),
    [sourceRows],
  )
  const selected = rows.find((incident) => incident.id === selectedId) ?? rows[0]
  const reportRows = rows.length > 0 ? rows : sourceRows
  const averageRisk =
    reportRows.length > 0 ? reportRows.reduce((sum, incident) => sum + incident.risk, 0) / reportRows.length : 0
  const highRiskCount = reportRows.filter((incident) => incident.risk >= 0.7).length
  const fallbackByScenario = caseRows.mode === 'local-demo' && strictRows.length === 0
  const workingApiMode = caseRows.mode === 'api'
  const complianceOn = complianceEnabled(complianceMode)
  const reportDisabled = complianceOn && !workingApiMode
  const totalCases = caseRows.total ?? sourceRows.length
  const pageNumber = Math.floor(pageOffset / pageLimit) + 1
  const hasNextPage = workingApiMode ? pageOffset + pageLimit < totalCases : false
  const hasPrevPage = workingApiMode && pageOffset > 0

  useEffect(() => {
    let cancelled = false
    if (!taktApiConfigured()) {
      setComplianceMode(null)
      return
    }
    fetchComplianceMode()
      .then((mode) => {
        if (!cancelled) {
          setComplianceMode(mode)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setComplianceMode(null)
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  function buildReport(rowsForReport: DemoIncident[]): string {
    const lines = [
      'ЛОКАЛЬНЫЙ ОТЧЁТ ИНТЕРФЕЙСА — БЕЗ ДОКАЗАТЕЛЬНОЙ СИЛЫ',
      'Этот отчёт сформирован в браузере и не является машинно-проверяемым доказательным артефактом.',
      '',
      'Отчёт по очереди инцидентов ТАКТ',
      `Сценарий: ${activeScenarioTitle}`,
      `Режим сегмента: ${modeLabels[segmentMode]}`,
      `Фаза: ${phaseLabels[shiftPhase]}`,
      `Статус: ${filter}`,
      `Инцидентов в отчёте: ${rowsForReport.length}`,
      `Средний индекс риска: ${formatRisk(averageRisk)}`,
      '',
      ...rowsForReport.map(
        (incident) =>
          `${incident.time}; ${incident.id}; ${incident.status}; риск ${formatRisk(incident.risk)}; ${incident.node}; ${incident.summary}`,
      ),
    ]
    return lines.join('\n')
  }

  function prepareReport() {
    if (reportDisabled) {
      setReportText('ЛОКАЛЬНЫЙ ОТЧЁТ ИНТЕРФЕЙСА — БЕЗ ДОКАЗАТЕЛЬНОЙ СИЛЫ\nНормативный режим блокирует локальные демо-отчёты очереди без серверного интерфейса.')
      return
    }
    setReportText(buildReport(reportRows))
  }

  function downloadReport() {
    if (reportDisabled) {
      setReportText('ЛОКАЛЬНЫЙ ОТЧЁТ ИНТЕРФЕЙСА — БЕЗ ДОКАЗАТЕЛЬНОЙ СИЛЫ\nНормативный режим блокирует локальные демо-отчёты очереди без серверного интерфейса.')
      return
    }
    const text = reportText || buildReport(reportRows)
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

  function resetStatusFilter() {
    setFilter('Все')
    setPageOffset(0)
  }

  function selectStatusFilter(item: IncidentStatus | 'Все') {
    setFilter(item)
    setPageOffset(0)
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">Очередь инцидентов</h1>
        <p className="mt-1 max-w-[72ch] text-[13px] text-[var(--fg-2)]">
          Триаж без массовых операций: каждый инцидент классифицируется оператором отдельно.
        </p>
      </div>
      <p className="text-[12px] text-[var(--fg-3)]" aria-live="polite">
        Сценарий: {activeScenarioTitle}. Режим: {modeLabels[segmentMode]}. Фаза: {phaseLabels[shiftPhase]}.
        {workingApiMode
          ? ` API: /cases${caseRows.loading ? ' - загружается' : ''}${caseRows.error ? ` - ${caseRows.error}` : ''}.`
          : fallbackByScenario
          ? ' Для этой пары режима и фазы событий нет, поэтому показана очередь выбранного сценария целиком.'
          : ' Очередь отфильтрована по выбранным режиму сегмента и фазе смены.'}
      </p>

      <div className="grid gap-3 md:grid-cols-4">
        <MetricTile label="Инциденты" value={reportRows.length} hint="В текущей отчётной выборке" />
        <MetricTile label="Высокий риск" value={highRiskCount} hint="Индекс риска 0,700 и выше" />
        <MetricTile label="Средний риск" value={formatRisk(averageRisk)} hint="С учётом ползунков риска" />
        <MetricTile label="Режим выборки" value={fallbackByScenario ? 'Сценарий' : 'Точно'} hint={fallbackByScenario ? 'Резерв по сценарию' : 'Режим и фаза совпали'} />
      </div>

      <div className="flex flex-wrap gap-2">
        {filters.map((item) => {
          const count = item === 'Все' ? sourceRows.length : statusCounts[item] ?? 0
          return (
            <Chip key={item} active={filter === item} disabled={!workingApiMode && item !== 'Все' && count === 0} onClick={() => selectStatusFilter(item)}>
              {item} {count}
            </Chip>
          )
        })}
        {filter !== 'Все' ? (
          <Button variant="ghost" onClick={resetStatusFilter}>
            Сбросить статус
          </Button>
        ) : null}
      </div>

      <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="mr-auto text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Отчёт по очереди</h2>
          <Button onClick={prepareReport} disabled={reportDisabled}>Сформировать отчёт</Button>
          <Button variant="ghost" onClick={downloadReport} disabled={reportDisabled}>
            Выгрузить отчёт
          </Button>
        </div>
        <p className="mt-2 text-[12px] text-[var(--fg-2)]">
          {reportDisabled
            ? 'Нормативный режим блокирует локальные демо-отчёты очереди без серверного интерфейса. Используйте серверные доказательные сценарии.'
            : 'Отчёт строится по строкам таблицы; если статус временно скрывает все строки, используется вся очередь выбранного сценария.'}
        </p>
        {reportText ? (
          <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3 font-mono text-[12px] text-[var(--fg-2)]">
            {reportText}
          </pre>
        ) : null}
      </section>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div>
          <DataTable columns={columns} rows={rows} selectedRowId={selectedId} onRowSelect={(row) => setSelectedId(row.id)} />
          {workingApiMode ? (
            <div className="flex flex-wrap items-center gap-2 rounded-b-takt border-x border-b border-[var(--line)] bg-[var(--bg-1)] p-3 text-[12px] text-[var(--fg-2)]">
              <span className="mr-auto" aria-live="polite">API-пагинация: страница {pageNumber}, всего {totalCases}, Link {caseRows.link ? 'есть' : 'нет'}</span>
              <Button variant="ghost" disabled={!hasPrevPage} onClick={() => setPageOffset(Math.max(0, pageOffset - pageLimit))}>
                Назад
              </Button>
              <Button variant="ghost" disabled={!hasNextPage} onClick={() => setPageOffset(pageOffset + pageLimit)}>
                Вперёд
              </Button>
            </div>
          ) : null}
          {rows.length === 0 ? (
            <div className="rounded-b-takt border-x border-b border-[var(--line)] bg-[var(--bg-1)] p-4 text-[13px] text-[var(--fg-2)]">
              По статусу «{filter}» в текущей выборке строк нет. Нажмите «Все» или «Сбросить статус», чтобы вернуть данные.
            </div>
          ) : null}
        </div>
        <aside className="takt-card p-4">
          <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Детали выбранного инцидента</h2>
          {selected ? (
            <>
              <p className="mt-2 font-mono text-[13px] text-[var(--fg-1)]">{selected.id}</p>
              <p className="mt-3 text-[13px] text-[var(--fg-2)]">{selected.summary}</p>
              <div className="mt-4">
                <RiskBadge value={selected.risk} />
              </div>
              <dl className="mt-4 grid gap-2 text-[12px]">
                <div><dt className="text-[var(--fg-3)]">Инвариант</dt><dd>{selected.invariant}</dd></div>
                <div><dt className="text-[var(--fg-3)]">Фаза</dt><dd>{selected.phase}</dd></div>
                <div><dt className="text-[var(--fg-3)]">Заявка</dt><dd>{selected.serviceDesk ?? 'нет'}</dd></div>
              </dl>
              <Link
                data-testid="incident-open-case"
                to={`/cases/${encodeURIComponent(selected.id)}`}
                className="mt-4 inline-flex rounded-takt border border-[var(--line)] px-3 py-1.5 text-[13px] font-medium text-[var(--fg-1)] transition-colors duration-150 hover:bg-[var(--bg-2)] takt-focus-ring"
              >
                Открыть карточку инцидента
              </Link>
            </>
          ) : (
            <p className="mt-3 text-[13px] text-[var(--fg-3)]">
              Для выбранного сценария, режима, фазы и статуса инцидентов нет.
            </p>
          )}
        </aside>
      </div>
      <p className="text-[12px] text-[var(--fg-3)]">Очередь использует воспроизводимый набор событий теплоэнергетики: котлоагрегаты, сетевые насосы, шлюзы АСУ ТП и сменные заявки.</p>
    </div>
  )
}


