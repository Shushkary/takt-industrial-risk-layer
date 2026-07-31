/**
 * Встроенный демонстрационный набор рабочего стола расследования.
 *
 * Повторяет цепочку стенда `scripts/stand_dataset.py`: заражение АРМ инженера,
 * обращение к внешнему адресу, соединение в технологический контур и запись
 * уставки на PLC — наблюдаемая всеми четырьмя классами источников ADR-001.
 *
 * Набор используется, только когда `VITE_TAKT_API_BASE_URL` не задан: витрина
 * должна оставаться демонстрируемой без поднятого backend. При настроенном API
 * экран работает на живых данных и этот файл не читается.
 */

import type { EntityCard, EntityKind, InvestigationWorkspace } from './types'

const BASE = '2026-06-01T09:0'

function at(minute: number, second: number): string {
  return `${BASE}${minute}:${String(second).padStart(2, '0')}+00:00`
}

const PIVOT = 'ews-01'
const USER = 'ivanov'
const PLC = 'plc-01'
const PLC_IP = '10.10.2.21'
const PIVOT_IP = '10.10.1.103'
const C2_IP = '203.0.113.10'
const C2_DOMAIN = 'evil.example'
const MALWARE_HASH = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'

const events: InvestigationWorkspace['events'] = [
  {
    event_id: 'edr-INC-001-1',
    observed_at: at(0, 0),
    source: 'edr',
    operation: 'PROCESS_START',
    protocol: 'endpoint',
    entities: { host_id: PIVOT, user_id: USER, process_id: 'p-101', parent_process_id: 'p-100', dst_address: C2_IP },
    artifacts: [{ type: 'hash', value: MALWARE_HASH }],
  },
  {
    event_id: 'ndr-INC-001-1',
    observed_at: at(0, 20),
    source: 'ndr',
    operation: 'C2_SUSPECT',
    protocol: 'DNS',
    entities: { host_id: PIVOT, src_address: PIVOT_IP, dst_address: C2_IP },
    artifacts: [{ type: 'domain', value: C2_DOMAIN }],
  },
  {
    event_id: 'siem-INC-001-1',
    observed_at: at(0, 30),
    source: 'siem',
    operation: 'SUSPICIOUS_OUTBOUND',
    protocol: 'siem',
    entities: { host_id: PIVOT, user_id: USER, src_address: PIVOT_IP, dst_address: C2_IP },
    artifacts: [{ type: 'domain', value: C2_DOMAIN }],
  },
  {
    event_id: 'edr-INC-001-2',
    observed_at: at(1, 30),
    source: 'edr',
    operation: 'NETWORK_CONNECT',
    protocol: 'endpoint',
    entities: { host_id: PIVOT, user_id: USER, process_id: 'p-102', parent_process_id: 'p-101', dst_address: PLC_IP },
    artifacts: [{ type: 'hash', value: MALWARE_HASH }],
  },
  {
    event_id: 'ndr-INC-001-2',
    observed_at: at(2, 0),
    source: 'ndr',
    operation: 'POLICY_VIOLATION',
    protocol: 'IEC104',
    entities: { host_id: PIVOT, src_address: PIVOT_IP, dst_address: PLC_IP },
    artifacts: [],
  },
  {
    event_id: 'siem-INC-001-2',
    observed_at: at(2, 30),
    source: 'siem',
    operation: 'OT_PROTOCOL_FROM_WORKSTATION',
    protocol: 'siem',
    entities: { host_id: PIVOT, user_id: USER, src_address: PIVOT_IP, dst_address: PLC_IP },
    artifacts: [{ type: 'address', value: PLC_IP }],
  },
  {
    event_id: 'siem-INC-001-3',
    observed_at: at(2, 50),
    source: 'siem',
    operation: 'MALWARE_HASH_MATCH',
    protocol: 'siem',
    entities: { host_id: PIVOT, user_id: USER, src_address: PIVOT_IP, dst_address: C2_IP },
    artifacts: [{ type: 'hash', value: MALWARE_HASH }],
  },
  {
    event_id: 'ot-INC-001-1',
    observed_at: at(3, 30),
    source: 'ot',
    operation: 'WRITE_SETPOINT',
    protocol: 'IEC104',
    entities: { host_id: PIVOT, user_id: USER, src_address: PIVOT_IP, dst_address: PLC_IP },
    artifacts: [{ type: 'process', value: 'boiler.pressure' }],
  },
  {
    event_id: 'ot-INC-001-2',
    observed_at: at(4, 0),
    source: 'ot',
    operation: 'ADMIN_LOGIN',
    protocol: 'IEC104',
    entities: { host_id: PLC, user_id: USER, src_address: PIVOT_IP, dst_address: PLC_IP },
    artifacts: [{ type: 'process', value: 'boiler.pressure' }],
  },
]

/** Повторяет `_case_graph` из `routers/workspace.py`: id узла — `kind:value`. */
function buildGraph(items: InvestigationWorkspace['events']): InvestigationWorkspace['graph'] {
  const nodes = new Map<string, InvestigationWorkspace['graph']['nodes'][number]>()
  const edges = new Map<string, InvestigationWorkspace['graph']['edges'][number]>()

  const node = (kind: string, value?: string | null): string => {
    if (!value) {
      return ''
    }
    const id = `${kind}:${value}`
    if (!nodes.has(id)) {
      nodes.set(id, { id, type: kind, value })
    }
    return id
  }

  for (const event of items) {
    const entities = event.entities ?? {}
    const host = node('host', entities.host_id)
    const user = node('user', entities.user_id)
    const process = node('process', entities.process_id)
    const parent = node('process', entities.parent_process_id)
    const src = node('address', entities.src_address)
    const dst = node('address', entities.dst_address)
    const artifactIds = event.artifacts.map((item) => node(item.type, item.value))

    const relations: Array<[string, string, string]> = [
      [user, process, 'initiated'],
      [parent, process, 'spawned'],
      [host, process, 'runs'],
      [host, user, 'acted_on'],
      [src, dst, 'network'],
      [host, dst, 'connects'],
      ...artifactIds.map((id) => [host, id, 'observed'] as [string, string, string]),
    ]
    for (const [source, target, type] of relations) {
      if (source && target && source !== target) {
        edges.set(`${source}|${target}|${type}`, { source, target, type, event_id: event.event_id })
      }
    }
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()] }
}

export const demoWorkspace: InvestigationWorkspace = {
  case: {
    case_id: 'demo-inc-001',
    title: 'Компрометация АРМ инженера с выходом в технологический контур',
    risk_score: 0.78,
    risk_class: 'HIGH',
    status: 'NEW',
    event_ids: events.map((event) => event.event_id),
    invariant_hits: ['blind_command', 'untrusted_ip_admin', 'new_node_airgap'],
    xai_summary:
      'Запуск неизвестного файла на инженерной станции, обращение к внешнему адресу и последующая ' +
      'запись уставки в контур: сочетание нетипично для окна наблюдения и роли узла.',
    audit_log: [
      `${at(0, 0)} | кейс создан автоматической корреляцией`,
      `${at(2, 30)} | события SIEM связаны по правилу user_destination`,
      `${at(3, 30)} | события OT связаны по правилу host_window`,
    ],
  },
  events,
  timeline: events.map((event) => ({
    id: event.event_id,
    at: event.observed_at,
    kind: 'event',
    source: event.source,
    label: event.operation,
  })),
  graph: buildGraph(events),
  findings: [
    {
      finding_id: 'f-001',
      text: 'Файл запущен из временного каталога и не встречался на других узлах сегмента.',
      author: 'analyst_l1',
    },
  ],
  artifacts: [
    { type: 'hash', value: MALWARE_HASH, source: 'edr', host_id: PIVOT },
    { type: 'domain', value: C2_DOMAIN, source: 'ndr', host_id: PIVOT },
    { type: 'address', value: C2_IP, source: 'siem', host_id: PIVOT },
    { type: 'host', value: PIVOT, source: 'edr', host_id: PIVOT },
    { type: 'process', value: 'boiler.pressure', source: 'ot', host_id: PLC },
  ],
  attack_chain: {
    entry_point: 'p-100',
    current_state: 'воздействие на технологический контур подтверждено телеметрией OT',
    steps: events.map((event, index) => ({
      order: index + 1,
      kind: index === 0 ? 'entry' : index >= events.length - 2 ? 'impact' : 'lateral',
      event_id: event.event_id,
      observed_at: event.observed_at,
      source: event.source,
      from_entity: event.entities?.src_address ?? event.entities?.host_id ?? '',
      to_entity: event.entities?.dst_address ?? '',
      operation: event.operation,
    })),
    artifacts: [
      { type: 'hash', value: MALWARE_HASH, event_id: 'edr-INC-001-1' },
      { type: 'domain', value: C2_DOMAIN, event_id: 'ndr-INC-001-1' },
    ],
  },
}

const activity = (peak: number): EntityCard['activity_by_hour'] =>
  Array.from({ length: 12 }, (_, index) => ({
    bucket: `2026-06-01T${String(index + 1).padStart(2, '0')}:00:00Z`,
    count: index === peak ? 9 : Math.max(0, 3 - Math.abs(peak - index)),
  }))

const demoCards: Record<string, EntityCard> = {
  [`host:${PIVOT}`]: {
    type: 'host',
    id: PIVOT,
    first_seen: at(0, 0),
    last_seen: at(3, 30),
    sources: ['edr', 'siem', 'ndr', 'ot'],
    event_count: 8,
    activity_by_hour: activity(8),
    typicality: {
      status: 'atypical',
      explanation: 'Узел впервые обращается к внешнему адресу и к промышленному протоколу в одном окне',
    },
    environment: events.slice(0, 5).map((event) => ({
      event_id: event.event_id,
      observed_at: event.observed_at,
      source: event.source,
      operation: event.operation,
      artifacts: event.artifacts,
    })),
    environment_total: 8,
    related_cases: ['demo-inc-001'],
  },
  [`user:${USER}`]: {
    type: 'user',
    id: USER,
    first_seen: at(0, 0),
    last_seen: at(4, 0),
    sources: ['edr', 'siem', 'ot'],
    event_count: 6,
    activity_by_hour: activity(9),
    typicality: { status: 'typical', explanation: 'Учётная запись регулярно активна в рабочую смену' },
    environment: events.slice(2, 6).map((event) => ({
      event_id: event.event_id,
      observed_at: event.observed_at,
      source: event.source,
      operation: event.operation,
      artifacts: event.artifacts,
    })),
    environment_total: 6,
    related_cases: ['demo-inc-001'],
  },
  ['process:p-101']: {
    type: 'process',
    id: 'p-101',
    first_seen: at(0, 0),
    last_seen: at(1, 30),
    sources: ['edr'],
    event_count: 1,
    activity_by_hour: activity(8),
    typicality: { status: 'first_seen', explanation: 'Процесс наблюдается впервые в сегменте' },
    environment: events.slice(0, 2).map((event) => ({
      event_id: event.event_id,
      observed_at: event.observed_at,
      source: event.source,
      operation: event.operation,
      artifacts: event.artifacts,
    })),
    environment_total: 1,
    related_cases: ['demo-inc-001'],
  },
}

export function demoEntityCard(kind: EntityKind, id: string): EntityCard {
  const known = demoCards[`${kind}:${id}`]
  if (known) {
    return known
  }
  return {
    type: kind,
    id,
    first_seen: at(0, 0),
    last_seen: at(4, 0),
    sources: ['edr'],
    event_count: 1,
    activity_by_hour: activity(8),
    typicality: { status: 'first_seen', explanation: 'Сущность наблюдается впервые в окне расследования' },
    environment: [],
    environment_total: 0,
    related_cases: ['demo-inc-001'],
  }
}

/** Демонстрационная выдача единого поиска: та же сущность на других узлах сегмента. */
export function demoSpread(artifactValue: string): InvestigationWorkspace['events'] {
  if (artifactValue === MALWARE_HASH) {
    return [
      ...events.filter((event) => event.artifacts.some((item) => item.value === artifactValue)),
      {
        event_id: 'edr-spread-1',
        observed_at: at(5, 10),
        source: 'edr',
        operation: 'PROCESS_START',
        protocol: 'endpoint',
        entities: { host_id: 'ews-02', user_id: 'petrova', process_id: 'p-501', dst_address: C2_IP },
        artifacts: [{ type: 'hash', value: MALWARE_HASH }],
      },
    ]
  }
  return events.filter((event) => event.artifacts.some((item) => item.value === artifactValue))
}

export const demoQueue = [
  {
    case_id: 'demo-inc-001',
    title: 'Компрометация АРМ инженера с выходом в контур',
    risk_class: 'HIGH',
    risk_score: 0.78,
    status: 'NEW',
    sources: ['edr', 'siem', 'ndr', 'ot'],
  },
  {
    case_id: 'demo-inc-002',
    title: 'Перебор пароля на сервере телеметрии',
    risk_class: 'MEDIUM',
    risk_score: 0.52,
    status: 'TRIAGE',
    sources: ['siem', 'ndr'],
  },
  {
    case_id: 'demo-inc-003',
    title: 'Отклонение периода опроса PLC',
    risk_class: 'MEDIUM',
    risk_score: 0.44,
    status: 'NEW',
    sources: ['ot'],
  },
  {
    case_id: 'demo-inc-004',
    title: 'Штатное обновление на рабочей станции',
    risk_class: 'LOW',
    risk_score: 0.18,
    status: 'NEW',
    sources: ['edr', 'siem'],
  },
]
