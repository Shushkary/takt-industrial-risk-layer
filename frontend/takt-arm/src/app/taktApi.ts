import { z } from 'zod'

export type FormalVerdictValue = 'легитимное' | 'нелегитимное' | 'неопределённое'


export type ApiMode = 'api' | 'local-demo'

export type TaktApiErrorBody = {
  error?: string
  detail?: unknown
  request_id?: string
}

export type HealthResponse = Record<string, unknown>
export type ReadyResponse = Record<string, unknown>

export type CasesQuery = {
  status?: string
  risk_class?: string
  case_id_prefix?: string
  limit?: number
  offset?: number
  sort?: string
}

export type CasesListResponse = {
  items: CaseListItem[]
  total: number | null
  link: string | null
}

export type CaseListItem = {
  case_id: string
  title?: string
  risk_score?: number
  risk_class?: string
  status?: string
  primary_asset_id?: string
  trigger_operation?: string
  operator_id?: string
  [key: string]: unknown
}

export type CasesStatsResponse = Record<string, unknown>

export type FormalVerdictRecord = {
  ts: string
  actor: string
  prev: FormalVerdictValue
  next: FormalVerdictValue
  score: number
  source: string
  permit_id: string
  reason: string
}

export type ManualPermitDetail = {
  permit_id: string
  case_id: string
  work_order_number: string
  actor: string
  created_at: string
  asset_id: string
  operation: string
  action_class: string
  verdict: string
  confidence: number
  rationale: string
  counterfactual: string
  executor: string
  approver: string
  valid_from: string
  valid_to: string
  document_status: string
  restrictions: string
  organizational_context_sha256: string
  note: string
}

export type CaseDetailResponse = {
  case_id: string
  title: string
  risk_score: number
  risk_class: string
  primary_asset_id: string
  trigger_operation: string
  operator_id: string
  xai_summary: string
  audit_log: string[]
  formal_verdict?: {
    value: FormalVerdictValue
    source: string
  }
  formal_verdict_records: FormalVerdictRecord[]
  manual_permits: ManualPermitDetail[]
  [key: string]: unknown
}

export type DecisionPayload = {
  status: 'NEW' | 'TRIAGE' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'EXPECTED_BEHAVIOR'
  reason: string
}

export type OperatorActionPayload = {
  reason?: string
  note?: string
}

export type EventIngestPayload = {
  observed_at: string
  protocol?: string
  operation: string
  asset_id: string
  operator_id?: string
  payload_size?: number
  source?: 'auth_logs' | 'network_events' | 'plc_polling' | 'service_desk' | 'unknown'
  event_id?: string
  payload?: Record<string, unknown>
}

export type EventBatchPayload = {
  events: EventIngestPayload[]
}

export type BatchAssessResponse = {
  results: Record<string, unknown>[]
  count: number
}

export type ManualPermitPayload = {
  work_order_number: string
  asset_id: string
  operation: string
  action_class?: string
  executor: string
  approver: string
  valid_from: string
  valid_to: string
  document_status: string
  restrictions?: string
  note?: string
}

type FormalVerdictConfirmationPayload = {
  verdict: FormalVerdictValue
  confidence: number
  reason: string
  note: string
}

type FormalVerdictConfirmationResponse = {
  record: FormalVerdictRecord
}

export type ForensicBundleManifest = {
  package_id: string
  case_id: string
  generated_at: string
  root_hash_sha256: string
  signature_status: string
  signature_ref: string
  process_suitability: string
  suitability_label: string
  suitability_checks: string[]
  items: Array<{
    path: string
    element_type: string
    source: string
    role: string
    media_type: string
    sha256: string
    checksum_algorithm: string
    chain_sha256: string
    size_bytes: number
    included_at: string
  }>
}

export type ForensicBundleDownload = {
  blob: Blob
  filename: string
  rootHash: string
  signatureStatus: string
}

export type InvariantCatalogItem = {
  id: string
  block_key: string
  block_label_ru: string
  title_ru: string
  experimental: boolean
}

export type InvariantCatalogResponse = InvariantCatalogItem[]
export type EventSourcesCatalogResponse = Record<string, unknown>
export type TopologyDemoGraphEdge = {
  src: string
  dst: string
  kind: string
}

export type TopologyDemoGraphResponse = {
  jump_host: string
  plc_hosts: string[]
  edges: TopologyDemoGraphEdge[]
  has_jump_bypass_pattern: boolean
}
export type ComplianceModeResponse = Record<string, unknown>
export type DataQualityReportResponse = Record<string, unknown>
export type ForensicReadinessResponse = Record<string, unknown>
export type AuditLedgerVerifyResponse = Record<string, unknown>
export type AuditEngagement = Record<string, unknown>
export type AuditEngagementsResponse = AuditEngagement[]
export type OperatorActionHistoryResponse = Record<string, unknown>
export type EvidenceChecklistResponse = Record<string, unknown>
export type ComplianceRemediationsResponse = Record<string, unknown>
export type RemediationAttemptPayload = {
  kind: string
  status?: 'recorded' | 'started' | 'completed' | 'failed'
  action?: string
  result?: string
  note?: string
}
export type RemediationRecheckPayload = {
  attempt_id: string
  note?: string
}
export type RemediationAttemptResponse = Record<string, unknown>
export type RemediationRecheckResponse = Record<string, unknown>
export type RemediationRecheckHistoryResponse = Record<string, unknown>
export type ForensicBundleVerifyResponse = Record<string, unknown>

type RequestOptions = {
  method?: 'GET' | 'POST'
  body?: unknown
  headers?: HeadersInit
}

const apiBaseUrl = import.meta.env.VITE_TAKT_API_BASE_URL?.replace(/\/+$/, '') ?? ''
const apiKey = import.meta.env.VITE_TAKT_API_KEY ?? ''
const AnyRecordSchema = z.record(z.string(), z.unknown())
const AnyObjectSchema = z.object({}).catchall(z.unknown())
const StringSchema = z.string()
const NumberSchema = z.number().finite()
const FormalVerdictValueSchema = z.enum(['легитимное', 'нелегитимное', 'неопределённое'])
const FormalVerdictRecordSchema = AnyObjectSchema.extend({
  ts: z.string(),
  actor: z.string(),
  prev: FormalVerdictValueSchema.catch('неопределённое'),
  next: FormalVerdictValueSchema.catch('неопределённое'),
  score: z.number().finite().catch(0),
  source: z.string(),
  permit_id: z.string().catch(''),
  reason: z.string().catch(''),
})
const ManualPermitDetailSchema = AnyObjectSchema.extend({
  permit_id: z.string().catch(''),
  case_id: z.string().catch(''),
  work_order_number: z.string(),
  actor: z.string().catch(''),
  created_at: z.string().catch(''),
  asset_id: z.string().catch(''),
  operation: z.string().catch(''),
  action_class: z.string().catch(''),
  verdict: z.string().catch('undetermined'),
  confidence: z.number().finite().catch(0),
  rationale: z.string().catch(''),
  counterfactual: z.string().catch(''),
  executor: z.string().catch(''),
  approver: z.string().catch(''),
  valid_from: z.string().catch(''),
  valid_to: z.string().catch(''),
  document_status: z.string().catch(''),
  restrictions: z.string().catch(''),
  organizational_context_sha256: z.string().catch(''),
  note: z.string().catch(''),
})
const CaseListItemSchema = AnyObjectSchema.extend({
  case_id: z.string(),
  title: z.string().optional(),
  risk_score: z.number().finite().optional(),
  risk_class: z.string().optional(),
  status: z.string().optional(),
  primary_asset_id: z.string().optional(),
  trigger_operation: z.string().optional(),
  operator_id: z.string().optional(),
})
const ForensicBundleManifestItemSchema = AnyObjectSchema.extend({
  path: z.string(),
  element_type: z.string().catch(''),
  source: z.string().catch(''),
  role: z.string().catch(''),
  media_type: z.string().catch(''),
  sha256: z.string().catch(''),
  checksum_algorithm: z.string().catch(''),
  chain_sha256: z.string().catch(''),
  size_bytes: z.number().finite().catch(0),
  included_at: z.string().catch(''),
})
const ForensicBundleManifestSchema = AnyObjectSchema.extend({
  package_id: z.string(),
  case_id: z.string(),
  generated_at: z.string(),
  root_hash_sha256: z.string(),
  signature_status: z.string().catch(''),
  signature_ref: z.string().catch(''),
  process_suitability: z.string().catch(''),
  suitability_label: z.string().catch(''),
  suitability_checks: z.array(z.string()).catch([]),
  items: z.array(ForensicBundleManifestItemSchema).catch([]),
})
const InvariantCatalogItemSchema = AnyObjectSchema.extend({
  id: z.string(),
  block_key: z.string().catch(''),
  block_label_ru: z.string().catch(''),
  title_ru: z.string().catch(''),
  experimental: z.boolean().catch(false),
})
const TopologyDemoGraphEdgeSchema = AnyObjectSchema.extend({
  src: z.string(),
  dst: z.string(),
  kind: z.string().catch(''),
})
const TopologyDemoGraphSchema = AnyObjectSchema.extend({
  jump_host: z.string(),
  plc_hosts: z.array(z.string()).catch([]),
  edges: z.array(TopologyDemoGraphEdgeSchema).catch([]),
  has_jump_bypass_pattern: z.boolean().catch(false),
})
const BatchAssessResponseSchema = AnyObjectSchema.extend({
  results: z.array(AnyRecordSchema).catch([]),
  count: z.number().finite().catch(0),
})
const ArtifactSchema = AnyObjectSchema.extend({
  type: z.string().catch(''),
  value: z.string().catch(''),
})
const EventSearchItemSchema = AnyObjectSchema.extend({
  event_id: z.string(),
  observed_at: z.string(),
  source: z.string().catch('unknown'),
  protocol: z.string().catch(''),
  operation: z.string().catch(''),
  entities: AnyRecordSchema.nullable().catch(null),
  artifacts: z.array(ArtifactSchema).catch([]),
  payload_size: z.number().finite().optional(),
  payload: AnyRecordSchema.optional(),
  operator_id: z.string().optional(),
  ingest_trust: z.number().finite().optional(),
})

function requestHeaders(json = false): HeadersInit {
  const headers: Record<string, string> = {}
  if (json) {
    headers['Content-Type'] = 'application/json'
  }
  if (apiKey) {
    headers['X-TAKT-API-Key'] = apiKey
  }
  return headers
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return AnyRecordSchema.safeParse(value).success
}

function isString(value: unknown): value is string {
  return StringSchema.safeParse(value).success
}

function isNumber(value: unknown): value is number {
  return NumberSchema.safeParse(value).success
}

function requireRecord(value: unknown, context: string): Record<string, unknown> {
  const parsed = AnyRecordSchema.safeParse(value)
  if (!parsed.success) {
    throw invalidApiResponse(context)
  }
  return parsed.data
}

export type CaseWorkspaceEvent = {
  event_id: string
  observed_at: string
  source: string
  operation: string
  protocol: string
  entities: Record<string, unknown> | null
  artifacts: Array<{ type: string; value: string }>
}

export type CaseWorkspaceResponse = {
  case: CaseDetailResponse
  events: CaseWorkspaceEvent[]
  timeline: Array<{ id: string; at: string; kind: string; source?: string; label: string }>
  graph: {
    nodes: Array<{ id: string; type: string; value: string }>
    edges: Array<{ source: string; target: string; type: string; event_id: string }>
  }
  findings: Array<{ finding_id: string; text: string; author: string }>
  artifacts: Array<{ type: string; value: string; source: string }>
  attack_chain: {
    entry_point: string
    current_state: string
    steps: Array<{
      order: number
      kind: string
      event_id: string
      observed_at: string
      source: string
      from_entity: string
      to_entity: string
      operation: string
    }>
    artifacts: Array<{ type: string; value: string; event_id: string }>
  }
}

export type EntityCardKind = 'host' | 'user' | 'process'

export type EntityCardResponse = {
  type: string
  id: string
  first_seen: string
  last_seen: string
  sources: string[]
  event_count: number
  activity_by_hour: Array<{ bucket: string; count: number }>
  typicality: { status: string; explanation: string }
  attributes: Record<string, unknown>
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

export type AttackChainResponse = {
  case_id: string
  entry_point: string
  current_state: string
  steps: Array<{
    order: number
    kind: string
    event_id: string
    observed_at: string
    source: string
    from_entity: string
    to_entity: string
    operation: string
  }>
  artifacts: Array<{ type: string; value: string; event_id: string }>
}

export type DecodeResponse = {
  input: string
  decodings: Array<{ kind: string; value: string; success: boolean; error?: string }>
}

export type CorrelationEditResponse = {
  case_id: string
  status: string
  event_ids: string[]
  risk_score: number
  related_cases: string[]
}

export type EventSearchQuery = {
  source?: string
  observed_from?: string
  observed_to?: string
  host_id?: string
  user_id?: string
  process_id?: string
  address?: string
  artifact_type?: string
  artifact_value?: string
  text?: string
  limit?: number
  offset?: number
}

export type EventSearchItem = CaseWorkspaceEvent & {
  payload_size?: number
  payload?: Record<string, unknown>
  operator_id?: string
  ingest_trust?: number
}

export type EventSearchResponse = {
  items: EventSearchItem[]
  total: number | null
}

function requireString(value: unknown, context: string): string {
  const parsed = StringSchema.safeParse(value)
  if (!parsed.success) {
    throw invalidApiResponse(context)
  }
  return parsed.data
}

function invalidApiResponse(context: string): Error {
  return new Error(`Некорректный ответ API: ${context}`)
}

function normalizeApiValidationError(error: unknown, context: string): never {
  if (error instanceof z.ZodError) {
    throw invalidApiResponse(context)
  }
  throw error
}

function parseFormalVerdictValue(value: unknown): FormalVerdictValue {
  return FormalVerdictValueSchema.catch('неопределённое').parse(value)
}

function parseFormalVerdictRecord(value: unknown): FormalVerdictRecord {
  const record = FormalVerdictRecordSchema.parse(value)
  return {
    ts: record.ts,
    actor: record.actor,
    prev: record.prev,
    next: record.next,
    score: record.score,
    source: record.source,
    permit_id: record.permit_id,
    reason: record.reason,
  }
}

function parseManualPermitDetail(value: unknown): ManualPermitDetail {
  const record = ManualPermitDetailSchema.parse(value)
  return {
    permit_id: record.permit_id,
    case_id: record.case_id,
    work_order_number: record.work_order_number,
    actor: record.actor,
    created_at: record.created_at,
    asset_id: record.asset_id,
    operation: record.operation,
    action_class: record.action_class,
    verdict: record.verdict,
    confidence: record.confidence,
    rationale: record.rationale,
    counterfactual: record.counterfactual,
    executor: record.executor,
    approver: record.approver,
    valid_from: record.valid_from,
    valid_to: record.valid_to,
    document_status: record.document_status,
    restrictions: record.restrictions,
    organizational_context_sha256: record.organizational_context_sha256,
    note: record.note,
  }
}

function parseCaseListItem(value: unknown): CaseListItem {
  const record = CaseListItemSchema.parse(value)
  return {
    ...record,
    case_id: record.case_id,
    title: record.title,
    risk_score: record.risk_score,
    risk_class: record.risk_class,
    status: record.status,
    primary_asset_id: record.primary_asset_id,
    trigger_operation: record.trigger_operation,
    operator_id: record.operator_id,
  }
}

function parseCaseDetail(value: unknown): CaseDetailResponse {
  const record = requireRecord(value, 'case detail')
  const auditLog = Array.isArray(record.audit_log) ? record.audit_log.filter(isString) : []
  const formalVerdict = isRecord(record.formal_verdict)
    ? {
        value: parseFormalVerdictValue(record.formal_verdict.value),
        source: isString(record.formal_verdict.source) ? record.formal_verdict.source : '',
      }
    : undefined
  const formalVerdictRecords = Array.isArray(record.formal_verdict_records)
    ? record.formal_verdict_records.map(parseFormalVerdictRecord)
    : []
  const manualPermits = Array.isArray(record.manual_permits)
    ? record.manual_permits.map(parseManualPermitDetail)
    : []

  return {
    ...record,
    case_id: requireString(record.case_id, 'case_id'),
    title: isString(record.title) ? record.title : requireString(record.case_id, 'case_id'),
    risk_score: isNumber(record.risk_score) ? record.risk_score : 0,
    risk_class: isString(record.risk_class) ? record.risk_class : '',
    primary_asset_id: isString(record.primary_asset_id) ? record.primary_asset_id : '',
    trigger_operation: isString(record.trigger_operation) ? record.trigger_operation : '',
    operator_id: isString(record.operator_id) ? record.operator_id : '',
    xai_summary: isString(record.xai_summary) ? record.xai_summary : '',
    audit_log: auditLog,
    formal_verdict: formalVerdict,
    formal_verdict_records: formalVerdictRecords,
    manual_permits: manualPermits,
  }
}

function parseManifest(value: unknown): ForensicBundleManifest {
  const record = ForensicBundleManifestSchema.parse(value)

  return {
    package_id: record.package_id,
    case_id: record.case_id,
    generated_at: record.generated_at,
    root_hash_sha256: record.root_hash_sha256,
    signature_status: record.signature_status,
    signature_ref: record.signature_ref,
    process_suitability: record.process_suitability,
    suitability_label: record.suitability_label,
    suitability_checks: record.suitability_checks,
    items: record.items,
  }
}

function parseInvariantCatalogItem(value: unknown): InvariantCatalogItem {
  const record = InvariantCatalogItemSchema.parse(value)
  return {
    id: record.id,
    block_key: record.block_key,
    block_label_ru: record.block_label_ru,
    title_ru: record.title_ru,
    experimental: record.experimental,
  }
}

function parseTopologyDemoGraph(value: unknown): TopologyDemoGraphResponse {
  const record = TopologyDemoGraphSchema.parse(value)
  return {
    jump_host: record.jump_host,
    plc_hosts: record.plc_hosts,
    edges: record.edges,
    has_jump_bypass_pattern: record.has_jump_bypass_pattern,
  }
}

function parseBatchAssessResponse(value: unknown): BatchAssessResponse {
  const record = BatchAssessResponseSchema.parse(value)
  return {
    results: record.results,
    count: record.count,
  }
}

function buildQuery(params: Record<string, string | number | undefined>): string {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') {
      query.set(key, String(value))
    }
  }
  const text = query.toString()
  return text ? `?${text}` : ''
}

async function apiRequest(path: string, options: RequestOptions = {}): Promise<Response | null> {
  if (!apiBaseUrl) {
    return null
  }

  return fetch(`${apiBaseUrl}${path}`, {
    method: options.method ?? 'GET',
    headers: {
      ...requestHeaders(options.body !== undefined),
      ...options.headers,
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  })
}

async function errorMessage(response: Response): Promise<string> {
  const text = await response.text()
  if (!text) {
    return `Ошибка API: ${response.status}`
  }
  try {
    const body = JSON.parse(text) as TaktApiErrorBody
    if (body.error || body.request_id) {
      return [body.error ?? `Ошибка API: ${response.status}`, body.request_id ? `request_id=${body.request_id}` : '']
        .filter(Boolean)
        .join(' ')
    }
  } catch {
    return text
  }
  return text
}

async function requestJson<T>(path: string, parser: (value: unknown) => T, options: RequestOptions = {}): Promise<T | null> {
  const response = await apiRequest(path, options)
  if (!response) {
    return null
  }
  if (!response.ok) {
    throw new Error(await errorMessage(response))
  }
  try {
    return parser(await response.json())
  } catch (error) {
    normalizeApiValidationError(error, path)
  }
}

export function taktApiConfigured(): boolean {
  return Boolean(apiBaseUrl)
}

export function taktApiMode(): ApiMode {
  return taktApiConfigured() ? 'api' : 'local-demo'
}

export async function fetchHealth(): Promise<HealthResponse | null> {
  return requestJson('/health', (value) => requireRecord(value, 'health'))
}

export async function fetchReady(): Promise<ReadyResponse | null> {
  return requestJson('/ready', (value) => requireRecord(value, 'ready'))
}

export async function fetchCases(query: CasesQuery = {}): Promise<CasesListResponse | null> {
  const response = await apiRequest(`/cases${buildQuery(query)}`)
  if (!response) {
    return null
  }
  if (!response.ok) {
    throw new Error(await errorMessage(response))
  }
  const body = await response.json()
  const rawItems = Array.isArray(body) ? body : isRecord(body) && Array.isArray(body.items) ? body.items : []
  try {
    return {
      items: rawItems.map(parseCaseListItem),
      total: Number.parseInt(response.headers.get('X-Total-Count') ?? '', 10) || null,
      link: response.headers.get('Link'),
    }
  } catch (error) {
    normalizeApiValidationError(error, '/cases')
  }
}

function parseEventSearchItem(value: unknown): EventSearchItem {
  const record = EventSearchItemSchema.parse(value)
  return {
    ...record,
    event_id: record.event_id,
    observed_at: record.observed_at,
    source: record.source,
    protocol: record.protocol,
    operation: record.operation,
    entities: record.entities,
    artifacts: record.artifacts,
  }
}

export async function fetchEventSearch(query: EventSearchQuery = {}): Promise<EventSearchResponse | null> {
  const response = await apiRequest(`/events/search${buildQuery(query)}`)
  if (!response) {
    return null
  }
  if (!response.ok) {
    throw new Error(await errorMessage(response))
  }
  const body = await response.json()
  if (!Array.isArray(body)) {
    throw invalidApiResponse('events search')
  }
  try {
    return {
      items: body.map(parseEventSearchItem),
      total: Number.parseInt(response.headers.get('X-Total-Count') ?? '', 10) || null,
    }
  } catch (error) {
    normalizeApiValidationError(error, '/events/search')
  }
}

export async function fetchCasesStats(): Promise<CasesStatsResponse | null> {
  return requestJson('/cases/stats', (value) => requireRecord(value, 'cases stats'))
}

export async function fetchCaseDetail(caseId: string): Promise<CaseDetailResponse | null> {
  return requestJson(`/cases/${encodeURIComponent(caseId)}`, parseCaseDetail)
}

export async function fetchCaseWorkspace(caseId: string): Promise<CaseWorkspaceResponse | null> {
  return requestJson(`/cases/${encodeURIComponent(caseId)}/workspace`, (value) => {
    const record = requireRecord(value, 'case workspace')
    return record as unknown as CaseWorkspaceResponse
  })
}

export async function addCaseFinding(
  caseId: string,
  text: string,
  eventIds: string[] = [],
): Promise<Record<string, unknown> | null> {
  return requestJson(`/cases/${encodeURIComponent(caseId)}/findings`, (value) => requireRecord(value, 'case finding'), {
    method: 'POST',
    body: { text, event_ids: eventIds, artifacts: [] },
  })
}

export async function addCaseArtifact(
  caseId: string,
  artifact: { type: string; value: string; host_id?: string },
): Promise<Record<string, unknown> | null> {
  return requestJson(`/cases/${encodeURIComponent(caseId)}/artifacts`, (value) => requireRecord(value, 'case artifact'), {
    method: 'POST',
    body: { ...artifact, verification_status: 'unverified' },
  })
}

export async function submitCaseDecision(caseId: string, payload: DecisionPayload): Promise<Record<string, unknown> | null> {
  return requestJson(`/cases/${encodeURIComponent(caseId)}/decision`, (value) => requireRecord(value, 'case decision'), {
    method: 'POST',
    body: payload,
  })
}

export async function recordCaseViewed(
  caseId: string,
  payload: OperatorActionPayload,
): Promise<Record<string, unknown> | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/operator-actions/viewed`,
    (value) => requireRecord(value, 'operator action'),
    { method: 'POST', body: payload },
  )
}

export async function requestAdditionalReview(
  caseId: string,
  payload: OperatorActionPayload,
): Promise<Record<string, unknown> | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/operator-actions/additional-review`,
    (value) => requireRecord(value, 'operator action'),
    { method: 'POST', body: payload },
  )
}

export async function ingestEventBatch(payload: EventBatchPayload): Promise<BatchAssessResponse | null> {
  return requestJson('/events/batch', parseBatchAssessResponse, {
    method: 'POST',
    body: payload,
  })
}

export async function attachManualPermit(
  caseId: string,
  payload: ManualPermitPayload,
): Promise<Record<string, unknown> | null> {
  return requestJson(`/cases/${encodeURIComponent(caseId)}/manual-permits`, (value) => requireRecord(value, 'manual permit'), {
    method: 'POST',
    body: payload,
  })
}

export async function fetchFormalVerdictHistory(caseId: string): Promise<Record<string, unknown> | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/formal-verdict/history`,
    (value) => requireRecord(value, 'formal verdict history'),
  )
}

export async function fetchOperatorActionHistory(caseId: string): Promise<OperatorActionHistoryResponse | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/operator-actions/history`,
    (value) => requireRecord(value, 'operator action history'),
  )
}

export async function sendFormalVerdictConfirmation(
  caseId: string,
  payload: FormalVerdictConfirmationPayload,
): Promise<FormalVerdictRecord> {
  if (!apiBaseUrl) {
    return {
      ts: new Date().toISOString(),
      actor: 'оператор',
      prev: 'неопределённое',
      next: payload.verdict,
      score: payload.confidence,
      source: 'operator_confirmation',
      permit_id: '',
      reason: payload.reason,
    }
  }

  const body = await requestJson(
    `/cases/${encodeURIComponent(caseId)}/formal-verdict/confirmation`,
    (value) => requireRecord(value, 'formal verdict confirmation') as FormalVerdictConfirmationResponse,
    { method: 'POST', body: payload },
  )
  try {
    return parseFormalVerdictRecord(body?.record)
  } catch (error) {
    normalizeApiValidationError(error, 'formal verdict confirmation record')
  }
}

export async function fetchInvariants(): Promise<InvariantCatalogResponse | null> {
  return requestJson('/invariants', (value) => {
    if (!Array.isArray(value)) {
      throw new Error('Некорректный ответ API: invariants')
    }
    return value.map(parseInvariantCatalogItem)
  })
}

export async function fetchEventSourcesCatalog(): Promise<EventSourcesCatalogResponse | null> {
  return requestJson('/catalog/event-sources', (value) => requireRecord(value, 'event sources catalog'))
}

export async function fetchTopologyDemoGraph(): Promise<TopologyDemoGraphResponse | null> {
  return requestJson('/topology/demo-graph', parseTopologyDemoGraph)
}

export async function fetchComplianceMode(): Promise<ComplianceModeResponse | null> {
  return requestJson('/compliance/mode', (value) => requireRecord(value, 'compliance mode'))
}

export async function fetchDataQualityReport(): Promise<DataQualityReportResponse | null> {
  return requestJson('/compliance/data-quality-report', (value) => requireRecord(value, 'data quality report'))
}

export async function fetchForensicReadiness(): Promise<ForensicReadinessResponse | null> {
  return requestJson('/compliance/forensic-readiness', (value) => requireRecord(value, 'forensic readiness'))
}

export async function fetchCaseEvidenceChecklist(caseId: string): Promise<EvidenceChecklistResponse | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/compliance/evidence-checklist`,
    (value) => requireRecord(value, 'evidence checklist'),
  )
}

export async function fetchCaseRemediations(caseId: string): Promise<ComplianceRemediationsResponse | null> {
  return requestJson(
    `/compliance/remediations${buildQuery({ case_id: caseId })}`,
    (value) => requireRecord(value, 'case remediations'),
  )
}

export async function recordCaseRemediationAttempt(
  caseId: string,
  payload: RemediationAttemptPayload,
): Promise<RemediationAttemptResponse | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/compliance/remediations`,
    (value) => requireRecord(value, 'remediation attempt'),
    { method: 'POST', body: payload },
  )
}

export async function recheckCaseRemediationReadiness(
  caseId: string,
  payload: RemediationRecheckPayload,
): Promise<RemediationRecheckResponse | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/compliance/remediations/recheck-readiness`,
    (value) => requireRecord(value, 'remediation readiness recheck'),
    { method: 'POST', body: payload },
  )
}

export async function fetchCaseRemediationRecheckHistory(
  caseId: string,
): Promise<RemediationRecheckHistoryResponse | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/compliance/remediations/recheck-readiness/history`,
    (value) => requireRecord(value, 'remediation readiness history'),
  )
}

export async function verifyOperationLedger(streamKey: string): Promise<AuditLedgerVerifyResponse | null> {
  return requestJson(
    `/audit-ledger/operations/verify${buildQuery({ stream_key: streamKey })}`,
    (value) => requireRecord(value, 'operation ledger verify'),
  )
}

export async function verifyCaseAuditLedger(caseId: string): Promise<AuditLedgerVerifyResponse | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/audit-ledger/verify`,
    (value) => requireRecord(value, 'case ledger verify'),
  )
}

export async function fetchAuditEngagements(): Promise<AuditEngagementsResponse | null> {
  return requestJson('/audit-engagements', (value) => {
    if (!Array.isArray(value)) {
      throw invalidApiResponse('audit engagements')
    }
    return value.map((item) => requireRecord(item, 'audit engagement'))
  })
}

export async function verifyForensicBundle(bundle: Blob): Promise<ForensicBundleVerifyResponse | null> {
  if (!apiBaseUrl) {
    return null
  }
  const response = await fetch(`${apiBaseUrl}/forensic-bundle/verify`, {
    method: 'POST',
    headers: requestHeaders(),
    body: bundle,
  })
  if (!response.ok) {
    throw new Error(await errorMessage(response))
  }
  try {
    return requireRecord(await response.json(), 'forensic bundle verify')
  } catch (error) {
    normalizeApiValidationError(error, '/forensic-bundle/verify')
  }
}

export async function fetchForensicBundleManifest(caseId: string): Promise<ForensicBundleManifest | null> {
  return requestJson(`/cases/${encodeURIComponent(caseId)}/forensic-bundle/manifest`, parseManifest)
}

function filenameFromDisposition(value: string | null, fallback: string): string {
  if (!value) {
    return fallback
  }
  const match = /filename="?([^";]+)"?/i.exec(value)
  return match?.[1] ?? fallback
}

export async function downloadForensicBundle(caseId: string): Promise<ForensicBundleDownload | null> {
  const response = await apiRequest(`/cases/${encodeURIComponent(caseId)}/forensic-bundle.zip`)
  if (!response) {
    return null
  }
  if (!response.ok) {
    throw new Error(await errorMessage(response))
  }
  return {
    blob: await response.blob(),
    filename: filenameFromDisposition(response.headers.get('Content-Disposition'), `takt-forensic-${caseId}.zip`),
    rootHash: response.headers.get('X-TAKT-Forensic-Root-Hash') ?? '',
    signatureStatus: response.headers.get('X-TAKT-Forensic-Signature-Status') ?? '',
  }
}


/** Карточка сущности ТЗ п. 5.5: историчность активности и окружение узла, пользователя, процесса. */
export async function fetchEntityCard(kind: EntityCardKind, entityId: string): Promise<EntityCardResponse | null> {
  return requestJson(
    `/entities/${encodeURIComponent(kind)}/${encodeURIComponent(entityId)}/card`,
    (value) => requireRecord(value, 'entity card') as unknown as EntityCardResponse,
  )
}

/** Реконструкция цепочки атаки ТЗ п. 4.6. */
export async function fetchCaseAttackChain(caseId: string): Promise<AttackChainResponse | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/attack-chain`,
    (value) => requireRecord(value, 'attack chain') as unknown as AttackChainResponse,
  )
}

/** Обогащение артефакта ТЗ п. 5.7: декодирование base64/URL в интерфейсе. */
export async function decodeArtifactValue(value: string): Promise<DecodeResponse | null> {
  return requestJson('/enrichment/decode', (body) => requireRecord(body, 'decode') as unknown as DecodeResponse, {
    method: 'POST',
    body: { value },
  })
}

/** Ручная корректировка связей ТЗ п. 5.3: аналитик привязывает событие к инциденту. */
export async function attachEventToCase(
  caseId: string,
  eventId: string,
  reason: string,
): Promise<CorrelationEditResponse | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/events/attach`,
    (value) => requireRecord(value, 'attach event') as unknown as CorrelationEditResponse,
    { method: 'POST', body: { event_id: eventId, reason } },
  )
}

/** Ручная корректировка связей ТЗ п. 5.3: аналитик оспаривает автоматическую связь. */
export async function detachEventFromCase(
  caseId: string,
  eventId: string,
  reason: string,
): Promise<CorrelationEditResponse | null> {
  return requestJson(
    `/cases/${encodeURIComponent(caseId)}/events/${encodeURIComponent(eventId)}/detach`,
    (value) => requireRecord(value, 'detach event') as unknown as CorrelationEditResponse,
    { method: 'POST', body: { reason } },
  )
}

/** Журнал находок ТЗ п. 5.6 (чтение). */
export async function fetchCaseFindings(caseId: string): Promise<Array<Record<string, unknown>> | null> {
  const response = await apiRequest(`/cases/${encodeURIComponent(caseId)}/findings`)
  if (!response) {
    return null
  }
  if (!response.ok) {
    throw new Error(await errorMessage(response))
  }
  const body = await response.json()
  return Array.isArray(body) ? (body as Array<Record<string, unknown>>) : []
}

/** Пакет реагирования ТЗ п. 5.11: артефакты с типом и узлом. */
export async function fetchCaseArtifacts(caseId: string): Promise<Array<Record<string, unknown>> | null> {
  const response = await apiRequest(`/cases/${encodeURIComponent(caseId)}/artifacts`)
  if (!response) {
    return null
  }
  if (!response.ok) {
    throw new Error(await errorMessage(response))
  }
  const body = await response.json()
  if (Array.isArray(body)) {
    return body as Array<Record<string, unknown>>
  }
  const items = isRecord(body) && Array.isArray(body.artifacts) ? body.artifacts : []
  return items as Array<Record<string, unknown>>
}
