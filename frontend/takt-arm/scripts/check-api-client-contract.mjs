import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const root = process.cwd()
const source = readFileSync(join(root, 'src', 'app', 'taktApi.ts'), 'utf8')

const requiredFragments = [
  'VITE_TAKT_API_BASE_URL',
  'VITE_TAKT_API_KEY',
  'requestJson',
  'errorMessage',
  'submitCaseDecision',
  'recordCaseViewed',
  'requestAdditionalReview',
  'ingestEventBatch',
  'attachManualPermit',
  'fetchAuditEngagements',
  'fetchOperatorActionHistory',
  'fetchCaseEvidenceChecklist',
  'fetchCaseRemediations',
  'recordCaseRemediationAttempt',
  'recheckCaseRemediationReadiness',
  'fetchCaseRemediationRecheckHistory',
  'verifyCaseAuditLedger',
  'verifyOperationLedger',
  '/health',
  '/ready',
  '/cases',
  '/cases/stats',
  '/decision',
  '/operator-actions/viewed',
  '/operator-actions/additional-review',
  '/operator-actions/history',
  '/events/batch',
  '/manual-permits',
  '/formal-verdict/history',
  '/invariants',
  '/catalog/event-sources',
  '/topology/demo-graph',
  '/compliance/mode',
  '/compliance/data-quality-report',
  '/compliance/forensic-readiness',
  '/compliance/evidence-checklist',
  '/compliance/remediations',
  '/compliance/remediations/recheck-readiness',
  '/audit-ledger/operations/verify',
  '/audit-ledger/verify',
  '/audit-engagements',
  '/forensic-bundle/verify',
  '/forensic-bundle/manifest',
  '/forensic-bundle.zip',
]

const forbiddenFragments = [
  '../demo',
  'demoIncidents',
  'localStorage',
]

const missing = requiredFragments.filter((fragment) => !source.includes(fragment))
const forbidden = forbiddenFragments.filter((fragment) => source.includes(fragment))

if (missing.length > 0 || forbidden.length > 0) {
  if (missing.length > 0) {
    console.error('Missing API client contract fragments:')
    for (const item of missing) {
      console.error(`- ${item}`)
    }
  }
  if (forbidden.length > 0) {
    console.error('Forbidden API client fragments:')
    for (const item of forbidden) {
      console.error(`- ${item}`)
    }
  }
  process.exit(1)
}

console.log('api_client_contract_ok=true')
