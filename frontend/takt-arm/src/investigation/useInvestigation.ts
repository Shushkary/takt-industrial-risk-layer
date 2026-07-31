import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  addCaseFinding,
  fetchCaseWorkspace,
  fetchCases,
  fetchEntityCard,
  fetchEventSearch,
  submitCaseDecision,
  taktApiConfigured,
} from '../app/taktApi'
import { demoEntityCard, demoQueue, demoSpread, demoWorkspace } from './demoInvestigation'
import type { EntityCard, EntityKind, InvestigationEvent, InvestigationWorkspace } from './types'

/**
 * Источник данных рабочего стола расследования.
 *
 * При заданном `VITE_TAKT_API_BASE_URL` экран работает на живом backend; иначе —
 * на встроенном демонстрационном наборе, чтобы витрину можно было показать без
 * поднятого API. Режим виден в интерфейсе, подмены живых данных демонстрационными
 * без явной пометки не происходит.
 */

export type QueueItem = {
  case_id: string
  title: string
  risk_class: string
  risk_score: number
  status: string
  sources: string[]
}

export type InvestigationMode = 'api' | 'demo'

function errorText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

export function useInvestigationMode(): InvestigationMode {
  return taktApiConfigured() ? 'api' : 'demo'
}

export function useIncidentQueue(mode: InvestigationMode) {
  const [items, setItems] = useState<QueueItem[]>(mode === 'demo' ? demoQueue : [])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(mode === 'api')

  useEffect(() => {
    if (mode === 'demo') {
      setItems(demoQueue)
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    fetchCases({ limit: 40, sort: 'risk_score_desc' })
      .then((response) => {
        if (cancelled || !response) {
          return
        }
        setItems(
          response.items.map((item) => ({
            case_id: item.case_id,
            title: item.title ?? item.case_id,
            risk_class: item.risk_class ?? 'LOW',
            risk_score: item.risk_score ?? 0,
            status: item.status ?? 'NEW',
            sources: typeof item.last_event_source === 'string' ? [item.last_event_source] : [],
          })),
        )
        setError(null)
      })
      .catch((cause) => {
        if (!cancelled) {
          setError(errorText(cause, 'Не удалось загрузить очередь инцидентов'))
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false)
        }
      })
    return () => {
      cancelled = true
    }
  }, [mode])

  return { items, error, loading }
}

export function useWorkspace(mode: InvestigationMode, caseId: string | null) {
  const [workspace, setWorkspace] = useState<InvestigationWorkspace | null>(mode === 'demo' ? demoWorkspace : null)
  const [loading, setLoading] = useState(mode === 'api')
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    if (mode === 'demo') {
      setWorkspace(demoWorkspace)
      setLoading(false)
      return () => undefined
    }
    if (!caseId) {
      setWorkspace(null)
      setLoading(false)
      return () => undefined
    }
    let cancelled = false
    setLoading(true)
    fetchCaseWorkspace(caseId)
      .then((response) => {
        if (cancelled || !response) {
          return
        }
        setWorkspace(response as unknown as InvestigationWorkspace)
        setError(null)
      })
      .catch((cause) => {
        if (!cancelled) {
          setError(errorText(cause, 'Не удалось загрузить рабочий стол инцидента'))
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false)
        }
      })
    return () => {
      cancelled = true
    }
  }, [mode, caseId])

  useEffect(() => load(), [load])

  const addFinding = useCallback(
    async (text: string, eventIds: string[]) => {
      if (mode === 'demo') {
        setWorkspace((current) =>
          current
            ? {
                ...current,
                findings: [
                  ...current.findings,
                  { finding_id: `local-${current.findings.length + 1}`, text, author: 'analyst_l1' },
                ],
              }
            : current,
        )
        return
      }
      if (!caseId) {
        return
      }
      await addCaseFinding(caseId, text, eventIds)
      load()
    },
    [mode, caseId, load],
  )

  const confirmCase = useCallback(async () => {
    if (mode === 'demo') {
      setWorkspace((current) =>
        current ? { ...current, case: { ...current.case, status: 'CONFIRMED' } } : current,
      )
      return
    }
    if (!caseId) {
      return
    }
    await submitCaseDecision(caseId, { status: 'CONFIRMED', reason: 'подтверждено аналитиком в едином окне' })
    load()
  }, [mode, caseId, load])

  return { workspace, loading, error, reload: load, addFinding, confirmCase }
}

export function useEntityCard(mode: InvestigationMode, kind: EntityKind | null, entityId: string | null) {
  const [card, setCard] = useState<EntityCard | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!kind || !entityId) {
      setCard(null)
      setError(null)
      return
    }
    if (mode === 'demo') {
      setCard(demoEntityCard(kind, entityId))
      setError(null)
      return
    }
    let cancelled = false
    setLoading(true)
    fetchEntityCard(kind, entityId)
      .then((response) => {
        if (!cancelled && response) {
          setCard(response as unknown as EntityCard)
          setError(null)
        }
      })
      .catch((cause) => {
        if (!cancelled) {
          setCard(null)
          setError(errorText(cause, 'Не удалось загрузить карточку сущности'))
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false)
        }
      })
    return () => {
      cancelled = true
    }
  }, [mode, kind, entityId])

  return { card, loading, error }
}

/** Оценка распространения (ТЗ п. 4.7): поиск того же артефакта по всем источникам. */
export function useSpreadSearch(mode: InvestigationMode) {
  const [results, setResults] = useState<InvestigationEvent[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState<{ type: string; value: string } | null>(null)

  const search = useCallback(
    async (artifactType: string, artifactValue: string) => {
      setQuery({ type: artifactType, value: artifactValue })
      setBusy(true)
      setError(null)
      try {
        if (mode === 'demo') {
          setResults(demoSpread(artifactValue))
          return
        }
        const response = await fetchEventSearch({
          artifact_type: artifactType,
          artifact_value: artifactValue,
          limit: 200,
        })
        setResults((response?.items ?? []) as unknown as InvestigationEvent[])
      } catch (cause) {
        setResults(null)
        setError(errorText(cause, 'Поиск по артефакту не выполнен'))
      } finally {
        setBusy(false)
      }
    },
    [mode],
  )

  const reset = useCallback(() => {
    setResults(null)
    setQuery(null)
    setError(null)
  }, [])

  return { results, busy, error, query, search, reset }
}

export function useSourceCounts(workspace: InvestigationWorkspace | null): Record<string, number> {
  return useMemo(() => {
    const counts: Record<string, number> = {}
    for (const event of workspace?.events ?? []) {
      counts[event.source] = (counts[event.source] ?? 0) + 1
    }
    return counts
  }, [workspace])
}
