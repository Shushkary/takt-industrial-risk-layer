/**
 * Модель данных рабочего стола расследования (ТЗ п. 9.1).
 *
 * Формы повторяют ответы backend: `GET /cases/{id}/workspace`,
 * `GET /entities/{type}/{id}/card`, `GET /cases/{id}/attack-chain`.
 * Один и тот же тип обслуживает и живой API, и встроенный демонстрационный
 * набор, поэтому экран не знает, откуда пришли данные.
 */

export type SourceClass = 'edr' | 'siem' | 'ndr' | 'ot'

export type InvestigationEvent = {
  event_id: string
  observed_at: string
  source: string
  operation: string
  protocol: string
  entities: {
    host_id?: string | null
    user_id?: string | null
    process_id?: string | null
    parent_process_id?: string | null
    src_address?: string | null
    dst_address?: string | null
  } | null
  artifacts: Array<{ type: string; value: string }>
}

export type InvestigationGraphNode = {
  id: string
  type: string
  value: string
}

export type InvestigationGraphEdge = {
  source: string
  target: string
  type: string
  event_id: string
}

export type InvestigationFinding = {
  finding_id: string
  text: string
  author: string
}

export type InvestigationArtifact = {
  type: string
  value: string
  source?: string
  host_id?: string
}

export type AttackChainStep = {
  order: number
  kind: string
  event_id: string
  observed_at: string
  source: string
  from_entity: string
  to_entity: string
  operation: string
}

export type InvestigationCase = {
  case_id: string
  title: string
  risk_score: number
  risk_class: string
  status: string
  event_ids: string[]
  invariant_hits: string[]
  xai_summary: string
  audit_log: string[]
}

export type InvestigationWorkspace = {
  case: InvestigationCase
  events: InvestigationEvent[]
  timeline: Array<{ id: string; at: string; kind: string; source?: string; label: string }>
  graph: { nodes: InvestigationGraphNode[]; edges: InvestigationGraphEdge[] }
  findings: InvestigationFinding[]
  artifacts: InvestigationArtifact[]
  attack_chain: {
    entry_point: string
    current_state: string
    steps: AttackChainStep[]
    artifacts: Array<{ type: string; value: string; event_id: string }>
  }
}

export type EntityKind = 'host' | 'user' | 'process'

export type EntityCard = {
  type: string
  id: string
  first_seen: string
  last_seen: string
  sources: string[]
  event_count: number
  activity_by_hour: Array<{ bucket: string; count: number }>
  typicality: { status: string; explanation: string }
  environment: Array<{
    event_id: string
    observed_at: string
    source: string
    operation: string
    artifacts: Array<{ type: string; value: string }>
  }>
  environment_total: number
  related_cases: string[]
}

export const SOURCE_LABELS: Record<string, string> = {
  edr: 'EDR',
  siem: 'SIEM',
  ndr: 'NDR',
  ot: 'OT / PT ISIM',
}

export const SOURCE_HINTS: Record<string, string> = {
  edr: 'Телеметрия конечной точки: процессы, хеши, локальный пользователь',
  siem: 'Агрегированный контекст SOC: правила и типизированные индикаторы',
  ndr: 'Сетевые потоки и сетевые детекты',
  ot: 'Промышленная телеметрия и технологический контекст',
}

/** Цвета источников. Значения продублированы в index.css как переменные --src-*. */
export const SOURCE_COLORS: Record<string, string> = {
  edr: '#38bdf8',
  siem: '#a78bfa',
  ndr: '#2dd4bf',
  ot: '#f59e0b',
}

export const NODE_KIND_LABELS: Record<string, string> = {
  host: 'Узел',
  user: 'Пользователь',
  process: 'Процесс',
  address: 'Адрес',
  hash: 'Хеш',
  file: 'Файл',
  domain: 'Домен',
  url: 'URL',
  account: 'Учётная запись',
  event: 'Событие',
}
