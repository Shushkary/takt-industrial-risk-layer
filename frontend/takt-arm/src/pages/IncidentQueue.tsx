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
  NORMAL: 'РЁС‚Р°С‚РЅС‹Р№',
  DEGRADED: 'Р”РµРіСЂР°РґР°С†РёСЏ',
  'AIR-GAP': 'РР·РѕР»СЏС†РёСЏ',
  STORM: 'РџРёРє РЅР°РіСЂСѓР·РєРё',
}
const phaseLabels: Record<ShiftPhase, string> = {
  WORK: 'Р Р°Р±РѕС‡Р°СЏ',
  NIGHT: 'РќРѕС‡СЊ',
  MAINT: 'РћР±СЃР»СѓР¶РёРІР°РЅРёРµ',
}

const columns: DataTableColumn<DemoIncident>[] = [
  { id: 'time', header: 'Р’СЂРµРјСЏ', cell: (row) => row.time },
  { id: 'node', header: 'РЈР·РµР»', cell: (row) => row.node },
  { id: 'invariant', header: 'РРЅРІР°СЂРёР°РЅС‚', cell: (row) => row.invariant },
  { id: 'risk', header: 'РРЅРґРµРєСЃ СЂРёСЃРєР°', align: 'right', cell: (row) => <RiskBadge value={row.risk} /> },
  { id: 'phase', header: 'Р¤Р°Р·Р°', cell: (row) => row.phase },
  { id: 'status', header: 'РЎС‚Р°С‚СѓСЃ', cell: (row) => row.status },
  { id: 'operator', header: 'РћРїРµСЂР°С‚РѕСЂ', cell: (row) => row.operator },
  { id: 'scenarioId', header: 'РЎС†РµРЅР°СЂРёР№', cell: (row) => scenarioTitleById.get(row.scenarioId) ?? row.scenarioId },
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
  const activeScenarioTitle = activeScenario?.title ?? 'РЎС†РµРЅР°СЂРёР№ РЅРµ РІС‹Р±СЂР°РЅ'
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
      'NON-EVIDENCE LOCAL UI REPORT',
      'Этот отчёт сформирован в браузере и не является машинно-проверяемым forensic-артефактом.',
      '',
      'РћС‚С‡С‘С‚ РїРѕ РѕС‡РµСЂРµРґРё РёРЅС†РёРґРµРЅС‚РѕРІ РўРђРљРў',
      `РЎС†РµРЅР°СЂРёР№: ${activeScenarioTitle}`,
      `Р РµР¶РёРј СЃРµРіРјРµРЅС‚Р°: ${modeLabels[segmentMode]}`,
      `Р¤Р°Р·Р°: ${phaseLabels[shiftPhase]}`,
      `РЎС‚Р°С‚СѓСЃ: ${filter}`,
      `РРЅС†РёРґРµРЅС‚РѕРІ РІ РѕС‚С‡С‘С‚Рµ: ${rowsForReport.length}`,
      `РЎСЂРµРґРЅРёР№ РёРЅРґРµРєСЃ СЂРёСЃРєР°: ${formatRisk(averageRisk)}`,
      '',
      ...rowsForReport.map(
        (incident) =>
          `${incident.time}; ${incident.id}; ${incident.status}; СЂРёСЃРє ${formatRisk(incident.risk)}; ${incident.node}; ${incident.summary}`,
      ),
    ]
    return lines.join('\n')
  }

  function prepareReport() {
    if (reportDisabled) {
      setReportText('NON-EVIDENCE LOCAL UI REPORT\nCompliance mode блокирует локальные демо-отчёты очереди без backend API.')
      return
    }
    setReportText(buildReport(reportRows))
  }

  function downloadReport() {
    if (reportDisabled) {
      setReportText('NON-EVIDENCE LOCAL UI REPORT\nCompliance mode блокирует локальные демо-отчёты очереди без backend API.')
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
        <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">РћС‡РµСЂРµРґСЊ РёРЅС†РёРґРµРЅС‚РѕРІ</h1>
        <p className="mt-1 max-w-[72ch] text-[13px] text-[var(--fg-2)]">
          РўСЂРёР°Р¶ Р±РµР· РјР°СЃСЃРѕРІС‹С… РѕРїРµСЂР°С†РёР№: РєР°Р¶РґС‹Р№ РёРЅС†РёРґРµРЅС‚ РєР»Р°СЃСЃРёС„РёС†РёСЂСѓРµС‚СЃСЏ РѕРїРµСЂР°С‚РѕСЂРѕРј РѕС‚РґРµР»СЊРЅРѕ.
        </p>
      </div>
      <p className="text-[12px] text-[var(--fg-3)]" aria-live="polite">
        РЎС†РµРЅР°СЂРёР№: {activeScenarioTitle}. Р РµР¶РёРј: {modeLabels[segmentMode]}. Р¤Р°Р·Р°: {phaseLabels[shiftPhase]}.
        {workingApiMode
          ? ` API: /cases${caseRows.loading ? ' - загружается' : ''}${caseRows.error ? ` - ${caseRows.error}` : ''}.`
          : fallbackByScenario
          ? ' Р”Р»СЏ СЌС‚РѕР№ РїР°СЂС‹ СЂРµР¶РёРјР° Рё С„Р°Р·С‹ СЃРѕР±С‹С‚РёР№ РЅРµС‚, РїРѕСЌС‚РѕРјСѓ РїРѕРєР°Р·Р°РЅР° РѕС‡РµСЂРµРґСЊ РІС‹Р±СЂР°РЅРЅРѕРіРѕ СЃС†РµРЅР°СЂРёСЏ С†РµР»РёРєРѕРј.'
          : ' РћС‡РµСЂРµРґСЊ РѕС‚С„РёР»СЊС‚СЂРѕРІР°РЅР° РїРѕ РІС‹Р±СЂР°РЅРЅС‹Рј СЂРµР¶РёРјСѓ СЃРµРіРјРµРЅС‚Р° Рё С„Р°Р·Рµ СЃРјРµРЅС‹.'}
      </p>

      <div className="grid gap-3 md:grid-cols-4">
        <MetricTile label="РРЅС†РёРґРµРЅС‚С‹" value={reportRows.length} hint="Р’ С‚РµРєСѓС‰РµР№ РѕС‚С‡С‘С‚РЅРѕР№ РІС‹Р±РѕСЂРєРµ" />
        <MetricTile label="Р’С‹СЃРѕРєРёР№ СЂРёСЃРє" value={highRiskCount} hint="РРЅРґРµРєСЃ СЂРёСЃРєР° 0,700 Рё РІС‹С€Рµ" />
        <MetricTile label="РЎСЂРµРґРЅРёР№ СЂРёСЃРє" value={formatRisk(averageRisk)} hint="РЎ СѓС‡С‘С‚РѕРј РїРѕР»Р·СѓРЅРєРѕРІ СЂРёСЃРєР°" />
        <MetricTile label="Р РµР¶РёРј РІС‹Р±РѕСЂРєРё" value={fallbackByScenario ? 'РЎС†РµРЅР°СЂРёР№' : 'РўРѕС‡РЅРѕ'} hint={fallbackByScenario ? 'Р РµР·РµСЂРІ РїРѕ СЃС†РµРЅР°СЂРёСЋ' : 'Р РµР¶РёРј Рё С„Р°Р·Р° СЃРѕРІРїР°Р»Рё'} />
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
            РЎР±СЂРѕСЃРёС‚СЊ СЃС‚Р°С‚СѓСЃ
          </Button>
        ) : null}
      </div>

      <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="mr-auto text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">РћС‚С‡С‘С‚ РїРѕ РѕС‡РµСЂРµРґРё</h2>
          <Button onClick={prepareReport} disabled={reportDisabled}>РЎС„РѕСЂРјРёСЂРѕРІР°С‚СЊ РѕС‚С‡С‘С‚</Button>
          <Button variant="ghost" onClick={downloadReport} disabled={reportDisabled}>
            Р’С‹РіСЂСѓР·РёС‚СЊ РѕС‚С‡С‘С‚
          </Button>
        </div>
        <p className="mt-2 text-[12px] text-[var(--fg-2)]">
          {reportDisabled
            ? 'Compliance mode блокирует локальные демо-отчёты очереди без backend API. Используйте серверные evidence-сценарии.'
            : 'РћС‚С‡С‘С‚ СЃС‚СЂРѕРёС‚СЃСЏ РїРѕ СЃС‚СЂРѕРєР°Рј С‚Р°Р±Р»РёС†С‹; РµСЃР»Рё СЃС‚Р°С‚СѓСЃ РІСЂРµРјРµРЅРЅРѕ СЃРєСЂС‹РІР°РµС‚ РІСЃРµ СЃС‚СЂРѕРєРё, РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ РІСЃСЏ РѕС‡РµСЂРµРґСЊ РІС‹Р±СЂР°РЅРЅРѕРіРѕ СЃС†РµРЅР°СЂРёСЏ.'}
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
          <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Р”РµС‚Р°Р»Рё РІС‹Р±СЂР°РЅРЅРѕРіРѕ РёРЅС†РёРґРµРЅС‚Р°</h2>
          {selected ? (
            <>
              <p className="mt-2 font-mono text-[13px] text-[var(--fg-1)]">{selected.id}</p>
              <p className="mt-3 text-[13px] text-[var(--fg-2)]">{selected.summary}</p>
              <div className="mt-4">
                <RiskBadge value={selected.risk} />
              </div>
              <dl className="mt-4 grid gap-2 text-[12px]">
                <div><dt className="text-[var(--fg-3)]">РРЅРІР°СЂРёР°РЅС‚</dt><dd>{selected.invariant}</dd></div>
                <div><dt className="text-[var(--fg-3)]">Р¤Р°Р·Р°</dt><dd>{selected.phase}</dd></div>
                <div><dt className="text-[var(--fg-3)]">Р—Р°СЏРІРєР°</dt><dd>{selected.serviceDesk ?? 'РЅРµС‚'}</dd></div>
              </dl>
              <Link
                data-testid="incident-open-case"
                to={`/cases/${encodeURIComponent(selected.id)}`}
                className="mt-4 inline-flex rounded-takt border border-[var(--line)] px-3 py-1.5 text-[13px] font-medium text-[var(--fg-1)] transition-colors duration-150 hover:bg-[var(--bg-2)] takt-focus-ring"
              >
                РћС‚РєСЂС‹С‚СЊ РєР°СЂС‚РѕС‡РєСѓ РёРЅС†РёРґРµРЅС‚Р°
              </Link>
            </>
          ) : (
            <p className="mt-3 text-[13px] text-[var(--fg-3)]">
              Р”Р»СЏ РІС‹Р±СЂР°РЅРЅРѕРіРѕ СЃС†РµРЅР°СЂРёСЏ, СЂРµР¶РёРјР°, С„Р°Р·С‹ Рё СЃС‚Р°С‚СѓСЃР° РёРЅС†РёРґРµРЅС‚РѕРІ РЅРµС‚.
            </p>
          )}
        </aside>
      </div>
      <p className="text-[12px] text-[var(--fg-3)]">РћС‡РµСЂРµРґСЊ РёСЃРїРѕР»СЊР·СѓРµС‚ РІРѕСЃРїСЂРѕРёР·РІРѕРґРёРјС‹Р№ РЅР°Р±РѕСЂ СЃРѕР±С‹С‚РёР№ С‚РµРїР»РѕСЌРЅРµСЂРіРµС‚РёРєРё: РєРѕС‚Р»РѕР°РіСЂРµРіР°С‚С‹, СЃРµС‚РµРІС‹Рµ РЅР°СЃРѕСЃС‹, С€Р»СЋР·С‹ РђРЎРЈ РўРџ Рё СЃРјРµРЅРЅС‹Рµ Р·Р°СЏРІРєРё.</p>
    </div>
  )
}


