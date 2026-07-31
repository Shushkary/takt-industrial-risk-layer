import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import assert from 'node:assert/strict'

const root = resolve(import.meta.dirname, '..')

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

const api = read('src/app/taktApi.ts')
const format = read('src/app/format.ts')
const appShell = read('src/layout/AppShell.tsx')
const caseRows = read('src/app/useCaseRows.ts')
const caseDetail = read('src/pages/CaseDetail.tsx')
const dataTable = read('src/components/ui/DataTable.tsx')
const riskBadge = read('src/components/ui/RiskBadge.tsx')
const queue = read('src/pages/IncidentQueue.tsx')
const invariants = read('src/pages/InvariantLibrary.tsx')
const topology = read('src/pages/TopologyMap.tsx')
const settings = read('src/pages/SettingsAudit.tsx')
const segmentOverview = read('src/pages/SegmentOverview.tsx')
const apiEvents = read('src/demo/apiEvents.ts')
const e2eSmoke = read('e2e/app-shell.spec.ts')
const packageJson = JSON.parse(read('package.json'))

const apiExports = [
  'fetchCases',
  'fetchCasesStats',
  'fetchCaseDetail',
  'submitCaseDecision',
  'recordCaseViewed',
  'requestAdditionalReview',
  'ingestEventBatch',
  'attachManualPermit',
  'fetchInvariants',
  'fetchTopologyDemoGraph',
  'fetchComplianceMode',
  'fetchDataQualityReport',
  'fetchForensicReadiness',
  'fetchAuditEngagements',
  'fetchOperatorActionHistory',
  'fetchCaseEvidenceChecklist',
  'fetchCaseRemediations',
  'recordCaseRemediationAttempt',
  'recheckCaseRemediationReadiness',
  'fetchCaseRemediationRecheckHistory',
  'verifyCaseAuditLedger',
  'verifyOperationLedger',
]

for (const name of apiExports) {
  assert.match(api, new RegExp(`export async function ${name}\\b`), `${name} must be exported by taktApi.ts`)
}

assert.match(api, /type ManualPermitPayload = \{[\s\S]*work_order_number: string[\s\S]*document_status: string/, 'manual permit payload must match backend fields')
assert.match(api, /function parseInvariantCatalogItem\b/, 'invariant catalog response must be parsed')
assert.match(api, /if \(!Array\.isArray\(value\)\)/, '/invariants must be validated as an array')
assert.match(api, /function parseTopologyDemoGraph\b/, 'topology demo graph response must be parsed')
assert.match(api, /has_jump_bypass_pattern/, 'topology bypass flag must be preserved')
assert.match(api, /from 'zod'/, 'API client must use zod for runtime validation')
assert.match(api, /AnyRecordSchema\.safeParse/, 'API client record parsing must use zod safeParse')
assert.match(api, /Некорректный ответ API/, 'API client validation errors must be Russian')
assert.doesNotMatch(api, /Invalid API response/, 'API client must not expose English validation errors')
for (const schemaName of [
  'CaseListItemSchema',
  'ManualPermitDetailSchema',
  'ForensicBundleManifestSchema',
  'InvariantCatalogItemSchema',
  'TopologyDemoGraphSchema',
  'BatchAssessResponseSchema',
]) {
  assert.match(api, new RegExp(`const ${schemaName}\\b`), `${schemaName} must define explicit API validation`)
  assert.match(api, new RegExp(`${schemaName}\\.parse\\(value\\)`), `${schemaName} must be used by response parsers`)
}
assert.match(api, /type EventIngestPayload = \{[\s\S]*observed_at: string[\s\S]*operation: string[\s\S]*asset_id: string/, 'event ingest payload must match backend fields')
assert.match(api, /export async function ingestEventBatch\b/, 'API client must post event batches')
assert.match(api, /\/events\/batch/, 'API client must target /events/batch')
assert.match(format, /Intl\.NumberFormat\('ru-RU'/, 'number formatting must use Russian Intl.NumberFormat')
for (const [name, source] of [
  ['risk badge', riskBadge],
  ['incident queue', queue],
  ['segment overview', segmentOverview],
  ['topology map', topology],
  ['case detail', caseDetail],
]) {
  assert.doesNotMatch(source, /toFixed\([^)]*\)\.replace\('\.', ','\)/, `${name} must not hand-roll Russian number formatting`)
}
assert.equal(packageJson.scripts['test:unit:vitest'], 'vitest run', 'unit gate must include Vitest')
assert.equal(packageJson.scripts['test:e2e:playwright'], 'playwright test', 'e2e gate must include Playwright')
for (const dependency of ['vitest', '@testing-library/react', 'msw', '@playwright/test']) {
  assert.ok(packageJson.devDependencies?.[dependency], `${dependency} must be installed for frontend tests`)
}

assert.match(appShell, /fetchComplianceMode\(\)/, 'app shell must load compliance mode from API')
assert.match(appShell, /fetchReady\(\)/, 'app shell must load backend readiness from API')
assert.match(appShell, /Нормативный режим включён/, 'app shell must show global compliance badge')
assert.match(appShell, /API готов/, 'app shell must show backend readiness badge')
assert.match(appShell, /Локальный демонстрационный режим/, 'app shell must show explicit local demo mode when API is absent')
assert.match(appShell, /const demoControlsDisabled = apiConfigured \|\| complianceOn/, 'app shell must disable local demo controls in API or compliance mode')
assert.match(appShell, /disabled=\{demoControlsDisabled\}/, 'app shell must apply the demo-control boundary to local controls')
assert.match(appShell, /Демо-режим отключён в API-режиме/, 'app shell must explain disabled demo controls in API mode')

assert.match(caseRows, /Promise\.all\(\[fetchCases\(\{ sort: 'risk_score_desc'/, 'case rows must load /cases from backend')
assert.match(caseRows, /setTotal\(cases\?\.total/, 'case rows must expose X-Total-Count from /cases')
assert.match(caseRows, /setLink\(cases\?\.link/, 'case rows must expose Link pagination header from /cases')
assert.match(queue, /caseRows\.mode === 'api' \? sourceRows/, 'API queue rows must not be re-filtered as demo rows')
assert.match(queue, /setPageOffset\(pageOffset \+ pageLimit\)/, 'incident queue must page forward through API offsets')
assert.match(queue, /API-пагинация: страница/, 'incident queue must display API pagination evidence')
assert.match(queue, /'CLOSED'\] as const/, 'incident queue closed filter must map to CLOSED API status')
assert.match(queue, /function selectStatusFilter\b[\s\S]*setPageOffset\(0\)/, 'incident queue status filter must reset API pagination offset')
assert.match(queue, /disabled=\{!workingApiMode && item !== 'Все' && count === 0\}/, 'incident queue API status filters must remain available as query filters')
assert.match(queue, /Нормативный режим блокирует локальные демо-отчёты очереди без серверного интерфейса/, 'incident queue must block local demo reports in compliance mode')
assert.match(queue, /fetchComplianceMode\(\)/, 'incident queue must read compliance mode before local report actions')
assert.match(queue, /onRowSelect=\{\(row\) => setSelectedId\(row\.id\)\}/, 'incident rows must use DataTable row selection')
assert.match(queue, /data-testid="incident-open-case"/, 'queue must expose a stable case-open control for e2e')
assert.match(queue, /aria-live="polite"/, 'incident queue must announce API loading and pagination changes')
assert.doesNotMatch(queue, /onClick=\{\(event\) => \{[\s\S]*closest\('tr\[data-row-id\]'\)/, 'incident queue must not use a wrapper div click handler for rows')
assert.match(dataTable, /onKeyDown=\{\(event\) => handleRowKeyDown\(event, row\)\}/, 'data table row selection must be keyboard accessible')
assert.match(dataTable, /role=\{onRowSelect \? 'button' : undefined\}/, 'selectable data table rows must expose an interactive role')
assert.match(dataTable, /aria-label=\{onRowSelect \? `Выбрать строку \$\{row\.id\}` : undefined\}/, 'selectable data table rows must expose an accessible row name')

assert.match(caseDetail, /attachManualPermit\(apiCaseId, payload\)/, 'case detail must attach manual permits through API')
assert.match(caseDetail, /submitCaseDecision\(apiCaseId/, 'case detail must submit operator decisions through API')
assert.match(caseDetail, /const blocked = reason\.trim\(\)\.length < 12/, 'case decisions must require an operator reason')
assert.match(caseDetail, /data-testid="case-decision-submit"/, 'case decision control must be covered by e2e')
assert.match(caseDetail, /requestAdditionalReview\(apiCaseId/, 'case detail must support additional review action')
assert.match(caseDetail, /fetchOperatorActionHistory\(apiCaseId\)/, 'case detail must load operator action history through API')
assert.match(caseDetail, /fetchCaseEvidenceChecklist\(apiCaseId\)/, 'case detail must load evidence checklist through API')
assert.match(caseDetail, /fetchCaseRemediations\(apiCaseId\)/, 'case detail must load case remediations through API')
assert.match(caseDetail, /fetchCaseRemediationRecheckHistory\(apiCaseId\)/, 'case detail must load remediation recheck history through API')
assert.match(caseDetail, /recordCaseRemediationAttempt\(apiCaseId/, 'case detail must record remediation attempts through API')
assert.match(caseDetail, /recheckCaseRemediationReadiness\(apiCaseId/, 'case detail must recheck remediation readiness through API')
assert.match(caseDetail, /verifyForensicBundle\(downloadedBundle\)/, 'case detail must verify downloaded forensic ZIP through API')
assert.match(caseDetail, /Проверить серверный доказательный пакет/, 'case detail must expose forensic ZIP verification control')
assert.match(caseDetail, /Зафиксировать устранение разрыва/, 'case detail must expose remediation attempt control')
assert.match(caseDetail, /Повторно проверить готовность/, 'case detail must expose readiness recheck control')
assert.match(caseDetail, /data-testid="case-manual-permit-submit"[\s\S]*type="submit"/, 'manual permit form must submit from its primary button')
assert.match(caseDetail, /data-testid="case-formal-verdict-submit"[\s\S]*type="submit"/, 'formal verdict form must submit from its primary button')
assert.match(caseDetail, /data-testid="case-forensic-verify"/, 'forensic verify control must be covered by e2e')
assert.match(caseDetail, /API-детали соответствия/, 'case detail must display API compliance detail')
assert.match(caseDetail, /ЛОКАЛЬНАЯ ЗАМЕТКА ОПЕРАТОРА — БЕЗ ДОКАЗАТЕЛЬНОЙ СИЛЫ/, 'local case export must be marked as non-evidence')
assert.match(caseDetail, /non-evidence-local-case-note-\$\{displayCaseId\}\.txt/, 'local case export filename must be marked as non-evidence')
assert.match(caseDetail, /серверный доказательный пакет/, 'local case UI must direct evidence use to server forensic ZIP')
assert.match(caseDetail, /Печать\/PDF без доказательной силы/, 'local print/PDF action must be visibly marked as non-evidence')
assert.match(caseDetail, /локальное демо-решение оператора без доказательной силы/, 'local demo operator decisions must be marked as non-evidence')
assert.match(caseDetail, /локальный демо-наряд без доказательной силы/, 'local demo manual permits must be marked as non-evidence')
assert.match(caseDetail, /локальный демо-вердикт без доказательной силы/, 'local demo formal verdicts must be marked as non-evidence')
assert.doesNotMatch(caseDetail, /active control/i, 'case detail must not introduce active control wording')

for (const [name, source] of [
  ['incident queue', queue],
  ['invariant library', invariants],
  ['settings audit', settings],
]) {
  assert.match(source, /ЛОКАЛЬНЫЙ ОТЧЁТ ИНТЕРФЕЙСА — БЕЗ ДОКАЗАТЕЛЬНОЙ СИЛЫ/, `${name} local report must be marked as non-evidence`)
  assert.match(source, /non-evidence-local-ui-report\.txt/, `${name} local report filename must be marked as non-evidence`)
}

assert.match(invariants, /fetchInvariants\(\)/, 'invariant library must load backend invariant catalog')
assert.match(invariants, /fetchEventSourcesCatalog\(\)/, 'invariant library must load backend event sources catalog')
assert.match(invariants, /fetchComplianceMode\(\)/, 'invariant library must read compliance mode before local report actions')
assert.match(invariants, /Нормативный режим блокирует локальные отчёты по инвариантам/, 'invariant library must block local reports in compliance mode')
assert.match(invariants, /disabled=\{localReportBlocked\}/, 'invariant report controls must be disabled in compliance mode')
assert.match(invariants, /серверный каталог не отображается/, 'invariant library must not claim local fallback is shown after API errors')
assert.match(invariants, /weight: 'не задан сервером'/, 'API invariant rows must not invent local weights')
assert.match(invariants, /threshold: 'не задан сервером'/, 'API invariant rows must not invent local thresholds')
assert.match(invariants, /triggerCount: null/, 'API invariant rows must not count demo incidents as API trigger history')
assert.match(invariants, /локальные веса, пороги и счётчики не используются/, 'API invariant catalog must explain that local metrics are not mixed in')
assert.match(topology, /fetchTopologyDemoGraph\(\)/, 'topology map must load backend demo graph')
assert.match(topology, /apiTopologyToVisual\(apiTopology, scenarioId\)/, 'topology visual map must be built from API graph when loaded')
assert.match(topology, /API \/topology\/demo-graph/, 'API topology links must be visibly attributed to backend graph data')
assert.match(topology, /nodeById\.get\(link\.from\)/, 'topology link details must use the active visual node set')
assert.match(topology, /const localDemoControlsDisabled = apiConfigured/, 'topology local scenario controls must be disabled when API is configured')
assert.match(topology, /disabled=\{localDemoControlsDisabled\}/, 'topology local controls must apply the API-mode disabled state')
assert.match(topology, /if \(isApiTopology\) \{[\s\S]*return clampRisk\(stateBase\)/, 'topology API graph risk must not use local slider values')
assert.match(topology, /не влияет на рабочий серверный граф/, 'topology must explain that sliders do not affect API graph data')
assert.match(topology, /Период и тип объекта отключены в API-режиме/, 'topology must explain local period/object filters are disabled in API mode')
assert.match(settings, /fetchComplianceMode\(\)/, 'settings audit must load compliance mode')
assert.match(settings, /fetchDataQualityReport\(\)/, 'settings audit must load data quality report')
assert.match(settings, /fetchForensicReadiness\(\)/, 'settings audit must load forensic readiness')
assert.match(settings, /fetchAuditEngagements\(\)/, 'settings audit must load audit engagements')
assert.match(settings, /function complianceEnabled\b/, 'settings audit must derive compliance mode before local report actions')
assert.match(settings, /Нормативный режим блокирует локальные отчёты настроек/, 'settings audit must block local settings reports in compliance mode')
assert.match(settings, /disabled=\{localReportBlocked\}/, 'settings audit report controls must be disabled in compliance mode')
assert.match(settings, /Локальное подтверждение изоляции \(без доказательной силы\)/, 'settings local air-gap confirmation must be visibly marked as non-evidence')
assert.match(settings, /verifyOperationLedger\(''\)/, 'settings audit must verify operation ledger through API')
assert.match(settings, /verifyCaseAuditLedger\(caseLedgerId\.trim\(\)\)/, 'settings audit must verify selected case ledger through API')
assert.match(settings, /Локальные отчёты интерфейса остаются без доказательной силы/, 'settings audit must label local reports as non-evidence near ledger checks')
assert.match(settings, /ingestEventBatch\(heatEnergyDemoEventBatch\)/, 'settings audit must ingest demo observations through API')
assert.match(settings, /не отправляет команды оборудованию/, 'demo ingest UI must preserve product boundary')
assert.match(segmentOverview, /\/cases\/stats total/, 'segment overview must display backend total case stats in API mode')
assert.match(segmentOverview, /by_last_event_source/, 'segment overview must display backend data source aggregates in API mode')
assert.match(segmentOverview, /by_risk_class/, 'segment overview must display backend risk-class aggregates in API mode')
assert.match(segmentOverview, /fetchHealth\(\)/, 'segment overview must load /health in API mode')
assert.match(segmentOverview, /fetchDataQualityReport\(\)/, 'segment overview must load backend data quality report in API mode')
assert.match(segmentOverview, /\/compliance\/data-quality-report open_cases/, 'segment overview must display backend data-quality evidence')

assert.match(apiEvents, /export const heatEnergyDemoEventBatch/, 'heat-energy demo event batch must be exported')
assert.match(apiEvents, /moscow-apartment-boiler/, 'demo ingest must include Moscow apartment heat scenario')
assert.match(apiEvents, /moscow-hospital-boiler/, 'demo ingest must include Moscow hospital heat scenario')
assert.match(apiEvents, /moscow-industrial-boiler/, 'demo ingest must include Moscow industrial heat scenario')
assert.match(apiEvents, /moscow-heat-network/, 'demo ingest must include Moscow heat-network scenario')
assert.match(apiEvents, /moscow-central-heat-point/, 'demo ingest must include Moscow central heat point scenario')
assert.match(apiEvents, /human_final_decision_required: true/, 'demo ingest must keep human-in-loop boundary')
assert.match(apiEvents, /no_active_control: true/, 'demo ingest must not model active control')
assert.doesNotMatch(apiEvents, /operation: 'WRITE'/, 'demo ingest must not include write-like equipment operations')

assert.ok((e2eSmoke.match(/\btest\(/g) ?? []).length >= 3, 'Playwright must cover at least three e2e scenarios')
assert.match(e2eSmoke, /queue row can be selected/, 'Playwright must cover queue to case decision flow')
assert.match(e2eSmoke, /manual permit and formal verdict/, 'Playwright must cover manual permit and formal verdict flow')
assert.match(e2eSmoke, /forensic export remains non-evidence/, 'Playwright must cover forensic export/verify boundary')

console.log('frontend_unit_contracts_ok=true')
