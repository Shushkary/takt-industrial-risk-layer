import { useEffect, useMemo, useState } from 'react'
import { demoIncidents, type DemoIncident, type DemoScenarioId, type DemoSegmentMode, type DemoShiftPhase, type IncidentStatus } from '../demo'
import { fetchCases, fetchCasesStats, taktApiMode, type CaseListItem, type CasesStatsResponse } from './taktApi'

export type CaseRowsState = {
  rows: DemoIncident[]
  stats: CasesStatsResponse | null
  total: number | null
  link: string | null
  loading: boolean
  error: string | null
  mode: 'api' | 'local-demo'
}

const fallbackStatus = demoIncidents[0]?.status
const knownStatuses = new Set<IncidentStatus>(demoIncidents.map((incident) => incident.status))

function apiStatusToIncidentStatus(status: string | undefined): IncidentStatus {
  if (status && knownStatuses.has(status as IncidentStatus)) {
    return status as IncidentStatus
  }
  const normalized = status?.toUpperCase() ?? ''
  if (normalized.includes('CLOSED')) {
    return demoIncidents.find((incident) => incident.status !== fallbackStatus)?.status ?? fallbackStatus
  }
  if (normalized.includes('FALSE')) {
    return demoIncidents.find((incident) => incident.risk < 0.4)?.status ?? fallbackStatus
  }
  if (normalized.includes('TRIAGE') || normalized.includes('NEW') || normalized.includes('OPEN')) {
    return demoIncidents.find((incident) => incident.risk >= 0.7)?.status ?? fallbackStatus
  }
  return fallbackStatus
}

function formatCaseTime(value: unknown): string {
  if (typeof value !== 'string' || !value) {
    return ''
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function caseToIncident(
  item: CaseListItem,
  scenarioId: DemoScenarioId,
  segmentMode: DemoSegmentMode,
  shiftPhase: DemoShiftPhase,
): DemoIncident {
  const title = item.title || item.case_id
  const risk = item.risk_score ?? 0
  return {
    id: item.case_id,
    time: formatCaseTime(item.created_at),
    node: item.primary_asset_id || 'asset',
    invariant: item.trigger_operation || item.risk_class || 'case',
    risk,
    phase: shiftPhase,
    status: apiStatusToIncidentStatus(item.status),
    operator: item.operator_id || 'operator',
    summary: title,
    scenarioId,
    mode: segmentMode,
    phaseKey: shiftPhase,
  }
}

export function useCaseRows({
  demoRows,
  scenarioId,
  segmentMode,
  shiftPhase,
  limit = 100,
  offset = 0,
  status,
}: {
  demoRows: DemoIncident[]
  scenarioId: DemoScenarioId
  segmentMode: DemoSegmentMode
  shiftPhase: DemoShiftPhase
  limit?: number
  offset?: number
  status?: string
}): CaseRowsState {
  const [apiRows, setApiRows] = useState<DemoIncident[] | null>(null)
  const [stats, setStats] = useState<CasesStatsResponse | null>(null)
  const [total, setTotal] = useState<number | null>(null)
  const [link, setLink] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const mode = taktApiMode()

  useEffect(() => {
    let cancelled = false
    if (mode !== 'api') {
      setApiRows(null)
      setStats(null)
      setTotal(null)
      setLink(null)
      setLoading(false)
      setError(null)
      return
    }

    setLoading(true)
    setError(null)
    Promise.all([fetchCases({ sort: 'risk_score_desc', limit, offset, status }), fetchCasesStats()])
      .then(([cases, nextStats]) => {
        if (cancelled) {
          return
        }
        setApiRows((cases?.items ?? []).map((item) => caseToIncident(item, scenarioId, segmentMode, shiftPhase)))
        setTotal(cases?.total ?? null)
        setLink(cases?.link ?? null)
        setStats(nextStats)
      })
      .catch((err: unknown) => {
        if (cancelled) {
          return
        }
        setApiRows([])
        setStats(null)
        setTotal(null)
        setLink(null)
        setError(err instanceof Error ? err.message : 'Ошибка API')
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [limit, mode, offset, scenarioId, segmentMode, shiftPhase, status])

  const rows = useMemo(() => (mode === 'api' ? apiRows ?? [] : demoRows), [apiRows, demoRows, mode])

  return {
    rows,
    stats,
    total,
    link,
    loading,
    error,
    mode,
  }
}
