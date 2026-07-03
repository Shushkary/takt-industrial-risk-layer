import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'

const server = setupServer()

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  server.resetHandlers()
  vi.unstubAllEnvs()
})
afterAll(() => server.close())

beforeEach(() => {
  vi.resetModules()
  vi.stubEnv('VITE_TAKT_API_BASE_URL', 'http://takt.test')
})

describe('taktApi runtime validation', () => {
  it('loads cases from the configured backend and preserves pagination headers', async () => {
    server.use(
      http.get('http://takt.test/cases', () =>
        HttpResponse.json(
          [
            {
              case_id: 'case-1',
              title: 'Проверка наряда',
              risk_score: 0.82,
              risk_class: 'HIGH',
              status: 'NEW',
              primary_asset_id: 'boiler-1',
              trigger_operation: 'READ',
              operator_id: 'operator-1',
            },
          ],
          {
            headers: {
              'X-Total-Count': '1',
              Link: '</cases?offset=1>; rel="next"',
            },
          },
        ),
      ),
    )

    const { fetchCases } = await import('./taktApi')
    const response = await fetchCases({ sort: 'risk_score_desc', limit: 1 })

    expect(response?.items).toHaveLength(1)
    expect(response?.items[0]?.case_id).toBe('case-1')
    expect(response?.total).toBe(1)
    expect(response?.link).toContain('offset=1')
  })

  it('normalizes invalid API payloads to Russian validation errors', async () => {
    server.use(http.get('http://takt.test/cases', () => HttpResponse.json([{ title: 'без идентификатора' }])))

    const { fetchCases } = await import('./taktApi')

    await expect(fetchCases()).rejects.toThrow('Некорректный ответ API: /cases')
  })

  it('reports local demo mode when the backend URL is absent', async () => {
    vi.unstubAllEnvs()
    vi.stubEnv('VITE_TAKT_API_BASE_URL', '')
    const { fetchHealth, taktApiConfigured, taktApiMode } = await import('./taktApi')

    expect(taktApiConfigured()).toBe(false)
    expect(taktApiMode()).toBe('local-demo')
    await expect(fetchHealth()).resolves.toBeNull()
  })

  it.each([
    ['health', '/health', 'fetchHealth'],
    ['ready', '/ready', 'fetchReady'],
    ['case stats', '/cases/stats', 'fetchCasesStats'],
    ['event sources', '/catalog/event-sources', 'fetchEventSourcesCatalog'],
    ['compliance mode', '/compliance/mode', 'fetchComplianceMode'],
    ['data quality', '/compliance/data-quality-report', 'fetchDataQualityReport'],
    ['forensic readiness', '/compliance/forensic-readiness', 'fetchForensicReadiness'],
  ])('loads %s response records', async (_label, path, functionName) => {
    server.use(http.get(`http://takt.test${path}`, () => HttpResponse.json({ ok: true, path })))
    const api = await import('./taktApi')

    const result = await (api[functionName as keyof typeof api] as () => Promise<Record<string, unknown> | null>)()

    expect(result).toMatchObject({ ok: true, path })
  })

  it('parses case detail with verdict records and manual permits', async () => {
    server.use(
      http.get('http://takt.test/cases/case-1', () =>
        HttpResponse.json({
          case_id: 'case-1',
          title: 'Case title',
          risk_score: 0.77,
          risk_class: 'HIGH',
          primary_asset_id: 'asset-1',
          trigger_operation: 'READ',
          operator_id: 'operator-1',
          xai_summary: 'summary',
          audit_log: ['line-1', 42, 'line-2'],
          formal_verdict: { value: 'легитимное', source: 'manual' },
          formal_verdict_records: [
            {
              ts: '2026-05-25T00:00:00Z',
              actor: 'operator',
              prev: 'неопределённое',
              next: 'легитимное',
              score: 0.9,
              source: 'operator_confirmation',
              permit_id: 'permit-1',
              reason: 'checked',
            },
          ],
          manual_permits: [
            {
              permit_id: 'permit-1',
              case_id: 'case-1',
              work_order_number: 'WO-1',
              confidence: 0.8,
            },
          ],
        }),
      ),
    )

    const { fetchCaseDetail } = await import('./taktApi')
    const detail = await fetchCaseDetail('case-1')

    expect(detail?.audit_log).toEqual(['line-1', 'line-2'])
    expect(detail?.formal_verdict?.value).toBe('легитимное')
    expect(detail?.formal_verdict_records[0]?.score).toBe(0.9)
    expect(detail?.manual_permits[0]?.work_order_number).toBe('WO-1')
  })

  it('sends API key and JSON body for operator decisions', async () => {
    vi.stubEnv('VITE_TAKT_API_KEY', 'secret-key')
    let capturedBody: unknown = null
    let capturedKey = ''
    server.use(
      http.post('http://takt.test/cases/case-1/decision', async ({ request }) => {
        capturedBody = await request.json()
        capturedKey = request.headers.get('X-TAKT-API-Key') ?? ''
        return HttpResponse.json({ saved: true })
      }),
    )

    const { submitCaseDecision } = await import('./taktApi')
    const response = await submitCaseDecision('case-1', { status: 'TRIAGE', reason: 'checked by operator' })

    expect(response).toMatchObject({ saved: true })
    expect(capturedBody).toEqual({ status: 'TRIAGE', reason: 'checked by operator' })
    expect(capturedKey).toBe('secret-key')
  })

  it.each([
    ['records case viewed', '/cases/case-1/operator-actions/viewed', 'recordCaseViewed'],
    ['requests additional review', '/cases/case-1/operator-actions/additional-review', 'requestAdditionalReview'],
  ])('%s', async (_label, path, functionName) => {
    let capturedBody: unknown = null
    server.use(
      http.post(`http://takt.test${path}`, async ({ request }) => {
        capturedBody = await request.json()
        return HttpResponse.json({ ok: true })
      }),
    )

    const api = await import('./taktApi')
    const result = await (
      api[functionName as keyof typeof api] as (
        caseId: string,
        payload: { reason: string; note: string },
      ) => Promise<Record<string, unknown> | null>
    )('case-1', { reason: 'operator action reason', note: 'operator note' })

    expect(result).toMatchObject({ ok: true })
    expect(capturedBody).toEqual({ reason: 'operator action reason', note: 'operator note' })
  })

  it('parses event batch ingest results', async () => {
    server.use(http.post('http://takt.test/events/batch', () => HttpResponse.json({ results: [{ case_id: 'case-1' }], count: 1 })))

    const { ingestEventBatch } = await import('./taktApi')
    const result = await ingestEventBatch({
      events: [{ observed_at: '2026-05-25T00:00:00Z', operation: 'READ', asset_id: 'asset-1' }],
    })

    expect(result).toEqual({ results: [{ case_id: 'case-1' }], count: 1 })
  })

  it('drops invalid event batch result records while preserving count', async () => {
    server.use(http.post('http://takt.test/events/batch', () => HttpResponse.json({ results: ['bad'], count: 1 })))

    const { ingestEventBatch } = await import('./taktApi')

    await expect(ingestEventBatch({ events: [] })).resolves.toEqual({ results: [], count: 1 })
  })

  it('attaches manual permit through the case API', async () => {
    let capturedBody: unknown = null
    server.use(
      http.post('http://takt.test/cases/case-1/manual-permits', async ({ request }) => {
        capturedBody = await request.json()
        return HttpResponse.json({ permit: { work_order_number: 'WO-1' } })
      }),
    )

    const { attachManualPermit } = await import('./taktApi')
    const response = await attachManualPermit('case-1', {
      work_order_number: 'WO-1',
      asset_id: 'asset-1',
      operation: 'READ',
      executor: 'engineer',
      approver: 'lead',
      valid_from: '2026-05-25T00:00',
      valid_to: '2026-05-25T01:00',
      document_status: 'approved',
    })

    expect(response).toMatchObject({ permit: { work_order_number: 'WO-1' } })
    expect(capturedBody).toMatchObject({ work_order_number: 'WO-1', document_status: 'approved' })
  })

  it('confirms formal verdict and parses the returned record', async () => {
    server.use(
      http.post('http://takt.test/cases/case-1/formal-verdict/confirmation', () =>
        HttpResponse.json({
          record: {
            ts: '2026-05-25T00:00:00Z',
            actor: 'operator',
            prev: 'неопределённое',
            next: 'нелегитимное',
            score: 0.95,
            source: 'operator_confirmation',
            permit_id: '',
            reason: 'checked',
          },
        }),
      ),
    )

    const { sendFormalVerdictConfirmation } = await import('./taktApi')
    const record = await sendFormalVerdictConfirmation('case-1', {
      verdict: 'нелегитимное',
      confidence: 0.95,
      reason: 'operator checked',
      note: 'note',
    })

    expect(record.next).toBe('нелегитимное')
    expect(record.score).toBe(0.95)
  })

  it('loads invariant catalog items with explicit schema validation', async () => {
    server.use(
      http.get('http://takt.test/invariants', () =>
        HttpResponse.json([{ id: 'inv-1', block_key: 'b1', block_label_ru: 'Блок', title_ru: 'Инвариант', experimental: true }]),
      ),
    )

    const { fetchInvariants } = await import('./taktApi')
    const items = await fetchInvariants()

    expect(items?.[0]).toMatchObject({ id: 'inv-1', title_ru: 'Инвариант', experimental: true })
  })

  it('rejects non-array invariant catalog payloads', async () => {
    server.use(http.get('http://takt.test/invariants', () => HttpResponse.json({ id: 'bad' })))

    const { fetchInvariants } = await import('./taktApi')

    await expect(fetchInvariants()).rejects.toThrow('Некорректный ответ API: invariants')
  })

  it('parses topology demo graph', async () => {
    server.use(
      http.get('http://takt.test/topology/demo-graph', () =>
        HttpResponse.json({
          jump_host: 'jump-1',
          plc_hosts: ['plc-1'],
          edges: [{ src: 'jump-1', dst: 'plc-1', kind: 'read' }],
          has_jump_bypass_pattern: true,
        }),
      ),
    )

    const { fetchTopologyDemoGraph } = await import('./taktApi')
    const graph = await fetchTopologyDemoGraph()

    expect(graph?.edges[0]).toMatchObject({ src: 'jump-1', dst: 'plc-1' })
    expect(graph?.has_jump_bypass_pattern).toBe(true)
  })

  it('rejects topology graphs without a jump host', async () => {
    server.use(http.get('http://takt.test/topology/demo-graph', () => HttpResponse.json({ edges: [] })))

    const { fetchTopologyDemoGraph } = await import('./taktApi')

    await expect(fetchTopologyDemoGraph()).rejects.toThrow('Некорректный ответ API: /topology/demo-graph')
  })

  it.each([
    ['formal verdict history', '/cases/case-1/formal-verdict/history', 'fetchFormalVerdictHistory'],
    ['operator action history', '/cases/case-1/operator-actions/history', 'fetchOperatorActionHistory'],
    ['evidence checklist', '/cases/case-1/compliance/evidence-checklist', 'fetchCaseEvidenceChecklist'],
    ['recheck history', '/cases/case-1/compliance/remediations/recheck-readiness/history', 'fetchCaseRemediationRecheckHistory'],
    ['case audit ledger', '/cases/case-1/audit-ledger/verify', 'verifyCaseAuditLedger'],
  ])('loads %s', async (_label, path, functionName) => {
    server.use(http.get(`http://takt.test${path}`, () => HttpResponse.json({ ok: true })))
    const api = await import('./taktApi')

    const result = await (api[functionName as keyof typeof api] as (caseId: string) => Promise<Record<string, unknown> | null>)(
      'case-1',
    )

    expect(result).toMatchObject({ ok: true })
  })

  it('loads case remediations using case_id query parameter', async () => {
    let caseId = ''
    server.use(
      http.get('http://takt.test/compliance/remediations', ({ request }) => {
        caseId = new URL(request.url).searchParams.get('case_id') ?? ''
        return HttpResponse.json({ items: [] })
      }),
    )

    const { fetchCaseRemediations } = await import('./taktApi')
    const result = await fetchCaseRemediations('case-1')

    expect(result).toMatchObject({ items: [] })
    expect(caseId).toBe('case-1')
  })

  it.each([
    ['records remediation attempt', '/cases/case-1/compliance/remediations', 'recordCaseRemediationAttempt'],
    ['rechecks remediation readiness', '/cases/case-1/compliance/remediations/recheck-readiness', 'recheckCaseRemediationReadiness'],
  ])('%s', async (_label, path, functionName) => {
    server.use(http.post(`http://takt.test${path}`, () => HttpResponse.json({ ok: true, attempt_id: 'attempt-1' })))
    const api = await import('./taktApi')

    const result = await (
      api[functionName as keyof typeof api] as (caseId: string, payload: Record<string, unknown>) => Promise<Record<string, unknown> | null>
    )('case-1', { attempt_id: 'attempt-1', kind: 'submit_decision', note: 'checked' })

    expect(result).toMatchObject({ ok: true })
  })

  it('verifies operation ledger with stream_key query parameter', async () => {
    let streamKey = ''
    server.use(
      http.get('http://takt.test/audit-ledger/operations/verify', ({ request }) => {
        streamKey = new URL(request.url).searchParams.get('stream_key') ?? ''
        return HttpResponse.json({ ok: true })
      }),
    )

    const { verifyOperationLedger } = await import('./taktApi')
    const result = await verifyOperationLedger('decision:case-1')

    expect(result).toMatchObject({ ok: true })
    expect(streamKey).toBe('decision:case-1')
  })

  it('loads audit engagements as an array of records', async () => {
    server.use(http.get('http://takt.test/audit-engagements', () => HttpResponse.json([{ id: 'eng-1' }])))

    const { fetchAuditEngagements } = await import('./taktApi')
    const result = await fetchAuditEngagements()

    expect(result).toEqual([{ id: 'eng-1' }])
  })

  it('rejects non-array audit engagements payloads', async () => {
    server.use(http.get('http://takt.test/audit-engagements', () => HttpResponse.json({ id: 'eng-1' })))

    const { fetchAuditEngagements } = await import('./taktApi')

    await expect(fetchAuditEngagements()).rejects.toThrow('Некорректный ответ API: audit engagements')
  })

  it('parses forensic bundle manifest items', async () => {
    server.use(
      http.get('http://takt.test/cases/case-1/forensic-bundle/manifest', () =>
        HttpResponse.json({
          package_id: 'pkg-1',
          case_id: 'case-1',
          generated_at: '2026-05-25T00:00:00Z',
          root_hash_sha256: 'abc',
          signature_status: 'unsigned',
          signature_ref: '',
          process_suitability: 'internal',
          suitability_label: 'ready',
          suitability_checks: ['ok'],
          items: [
            {
              path: 'audit.txt',
              element_type: 'audit',
              source: 'case',
              role: 'evidence',
              media_type: 'text/plain',
              sha256: 'def',
              checksum_algorithm: 'sha256',
              chain_sha256: 'chain',
              size_bytes: 12,
              included_at: '2026-05-25T00:00:00Z',
            },
          ],
        }),
      ),
    )

    const { fetchForensicBundleManifest } = await import('./taktApi')
    const manifest = await fetchForensicBundleManifest('case-1')

    expect(manifest?.items[0]?.path).toBe('audit.txt')
    expect(manifest?.root_hash_sha256).toBe('abc')
  })

  it('rejects forensic manifests without a package id', async () => {
    server.use(http.get('http://takt.test/cases/case-1/forensic-bundle/manifest', () => HttpResponse.json({ case_id: 'case-1' })))

    const { fetchForensicBundleManifest } = await import('./taktApi')

    await expect(fetchForensicBundleManifest('case-1')).rejects.toThrow(
      'Некорректный ответ API: /cases/case-1/forensic-bundle/manifest',
    )
  })

  it('downloads forensic bundle metadata and filename', async () => {
    server.use(
      http.get('http://takt.test/cases/case-1/forensic-bundle.zip', () =>
        new HttpResponse(new TextEncoder().encode('zip').buffer, {
          headers: {
            'Content-Disposition': 'attachment; filename="bundle.zip"',
            'X-TAKT-Forensic-Root-Hash': 'root',
            'X-TAKT-Forensic-Signature-Status': 'unsigned',
          },
        }),
      ),
    )

    const { downloadForensicBundle } = await import('./taktApi')
    const bundle = await downloadForensicBundle('case-1')

    expect(bundle?.filename).toBe('bundle.zip')
    expect(bundle?.rootHash).toBe('root')
    expect(bundle?.signatureStatus).toBe('unsigned')
  })

  it('posts raw blob to forensic bundle verification endpoint', async () => {
    let contentType = ''
    server.use(
      http.post('http://takt.test/forensic-bundle/verify', ({ request }) => {
        contentType = request.headers.get('Content-Type') ?? ''
        return HttpResponse.json({ ok: true, root_hash_sha256: 'root' })
      }),
    )

    const { verifyForensicBundle } = await import('./taktApi')
    const result = await verifyForensicBundle(new Blob(['zip'], { type: 'application/zip' }))

    expect(result).toMatchObject({ ok: true, root_hash_sha256: 'root' })
    expect(contentType).toBe('application/zip')
  })

  it('does not verify forensic bundles when the API is not configured', async () => {
    vi.unstubAllEnvs()
    vi.stubEnv('VITE_TAKT_API_BASE_URL', '')
    const { verifyForensicBundle } = await import('./taktApi')

    await expect(verifyForensicBundle(new Blob(['zip']))).resolves.toBeNull()
  })

  it('returns API error text with request id when the backend rejects a request', async () => {
    server.use(
      http.get('http://takt.test/health', () =>
        HttpResponse.json({ error: 'backend failed', request_id: 'req-1' }, { status: 503 }),
      ),
    )

    const { fetchHealth } = await import('./taktApi')

    await expect(fetchHealth()).rejects.toThrow('backend failed request_id=req-1')
  })
})
