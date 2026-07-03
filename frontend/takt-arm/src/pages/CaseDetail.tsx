import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useParams } from 'react-router-dom'
import { CheckCircle2, FileCheck2, ShieldCheck } from 'lucide-react'
import { Button } from '../components/ui/Button'
import { RiskBadge } from '../components/ui/RiskBadge'
import { formatRisk } from '../app/format'
import {
  attachManualPermit,
  downloadForensicBundle,
  fetchCaseEvidenceChecklist,
  fetchCaseDetail,
  fetchCaseRemediations,
  fetchCaseRemediationRecheckHistory,
  fetchForensicBundleManifest,
  fetchOperatorActionHistory,
  recordCaseViewed,
  recordCaseRemediationAttempt,
  recheckCaseRemediationReadiness,
  requestAdditionalReview,
  sendFormalVerdictConfirmation,
  submitCaseDecision,
  taktApiConfigured,
  verifyForensicBundle,
  type CaseDetailResponse,
  type ComplianceRemediationsResponse,
  type DecisionPayload,
  type EvidenceChecklistResponse,
  type ForensicBundleManifest,
  type FormalVerdictRecord,
  type FormalVerdictValue,
  type ManualPermitDetail,
  type ManualPermitPayload,
  type OperatorActionHistoryResponse,
  type RemediationRecheckHistoryResponse,
} from '../app/taktApi'
import {
  demoAuditEvents,
  demoIncidents,
  demoScenarios,
  selectDemoTopology,
  useDemoStore,
  type IncidentStatus,
} from '../demo'

const statusLabels: IncidentStatus[] = ['Разбор', 'Подтверждён', 'Ложное срабатывание', 'Ожидаемое поведение', 'Закрыт']
const verdictLabels: FormalVerdictValue[] = ['неопределённое', 'легитимное', 'нелегитимное']
const verdictTone: Record<FormalVerdictValue, string> = {
  неопределённое: 'border-[var(--amber-1)] text-[var(--amber-1)]',
  легитимное: 'border-[var(--teal-1)] text-[var(--teal-1)]',
  нелегитимное: 'border-[var(--risk-high)] text-[var(--risk-high)]',
}
const apiStatusByLabel = new Map<IncidentStatus, DecisionPayload['status']>(
  statusLabels.map((label, index) => {
    const apiStatuses: DecisionPayload['status'][] = [
      'TRIAGE',
      'CONFIRMED',
      'FALSE_POSITIVE',
      'EXPECTED_BEHAVIOR',
      'CONFIRMED',
    ]
    return [label, apiStatuses[index] ?? 'TRIAGE']
  }),
)

function recordArray(value: unknown, key: string): Record<string, unknown>[] {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return []
  }
  const raw = (value as Record<string, unknown>)[key]
  return Array.isArray(raw) ? raw.filter((item): item is Record<string, unknown> => typeof item === 'object' && item !== null && !Array.isArray(item)) : []
}

const defaultManualPermit = (assetId: string, operation: string): ManualPermitPayload => ({
  work_order_number: '',
  asset_id: assetId,
  operation,
  action_class: '',
  executor: '',
  approver: '',
  valid_from: '',
  valid_to: '',
  document_status: 'approved',
  restrictions: '',
  note: '',
})

const remediationKindLabels: Record<string, string> = {
  attach_manual_permit: 'Прикрепить ручной наряд',
  generate_forensic_bundle: 'Сформировать forensic bundle',
  ingest_telemetry: 'Загрузить телеметрию',
  rerun_assessment: 'Повторить оценку',
  submit_decision: 'Передать решение оператора',
}

const stateLabels: Record<string, string> = {
  local: 'локальный режим',
  loading: 'загружается',
  loaded: 'загружено',
  error: 'ошибка',
  idle: 'ожидание',
  saving: 'сохранение',
  saved: 'сохранено',
  ready: 'готово',
  verifying: 'проверяется',
  verified: 'проверено',
}

function displayState(value: string): string {
  return stateLabels[value] ?? value
}

export function CaseDetail() {
  const { id } = useParams()
  const { riskControls } = useDemoStore()
  const decodedId = useMemo(() => {
    if (!id) {
      return undefined
    }
    try {
      return decodeURIComponent(id)
    } catch {
      return id
    }
  }, [id])
  const incident = useMemo(() => demoIncidents.find((item) => item.id === decodedId) ?? demoIncidents[0], [decodedId])
  const apiCaseId = decodedId ?? incident.id
  const [caseDetail, setCaseDetail] = useState<CaseDetailResponse | null>(null)
  const [loadState, setLoadState] = useState<'local' | 'loading' | 'loaded' | 'error'>(
    taktApiConfigured() ? 'loading' : 'local',
  )
  const [status, setStatus] = useState<IncidentStatus>(incident.status)
  const [reason, setReason] = useState('')
  const [formalVerdict, setFormalVerdict] = useState<FormalVerdictValue>('неопределённое')
  const [formalReason, setFormalReason] = useState('')
  const [formalNote, setFormalNote] = useState('')
  const [confidence, setConfidence] = useState(90)
  const [records, setRecords] = useState<FormalVerdictRecord[]>([])
  const [operatorHistory, setOperatorHistory] = useState<OperatorActionHistoryResponse | null>(null)
  const [evidenceChecklist, setEvidenceChecklist] = useState<EvidenceChecklistResponse | null>(null)
  const [caseRemediations, setCaseRemediations] = useState<ComplianceRemediationsResponse | null>(null)
  const [recheckHistory, setRecheckHistory] = useState<RemediationRecheckHistoryResponse | null>(null)
  const [complianceDetailState, setComplianceDetailState] = useState<'local' | 'loading' | 'loaded' | 'error'>(
    taktApiConfigured() ? 'loading' : 'local',
  )
  const [remediationKind, setRemediationKind] = useState('attach_manual_permit')
  const [remediationNote, setRemediationNote] = useState('')
  const [latestAttemptId, setLatestAttemptId] = useState('')
  const [remediationState, setRemediationState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [recheckState, setRecheckState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [localAudit, setLocalAudit] = useState<string[]>([])
  const [decisionSaved, setDecisionSaved] = useState(false)
  const [decisionState, setDecisionState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [reviewState, setReviewState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [manualPermit, setManualPermit] = useState<ManualPermitPayload>(() =>
    defaultManualPermit(incident.node, incident.invariant),
  )
  const [manualPermits, setManualPermits] = useState<ManualPermitDetail[]>([])
  const [permitState, setPermitState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [documentPrepared, setDocumentPrepared] = useState(false)
  const [submitState, setSubmitState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [bundleManifest, setBundleManifest] = useState<ForensicBundleManifest | null>(null)
  const [downloadedBundle, setDownloadedBundle] = useState<Blob | null>(null)
  const [bundleVerifyState, setBundleVerifyState] = useState<'idle' | 'verifying' | 'verified' | 'error'>('idle')
  const [bundleVerifyResult, setBundleVerifyResult] = useState('')
  const [bundleState, setBundleState] = useState<'idle' | 'loading' | 'ready' | 'error' | 'local'>(
    taktApiConfigured() ? 'loading' : 'local',
  )
  const [bundleMessage, setBundleMessage] = useState('')
  const blocked = reason.trim().length < 12
  const verdictBlocked = formalReason.trim().length < 12 || submitState === 'saving'
  const displayCaseId = caseDetail?.case_id ?? incident.id
  const displayTitle = caseDetail?.title ?? incident.summary
  const displayRisk = caseDetail?.risk_score ?? incident.risk
  const displayAsset = caseDetail?.primary_asset_id || incident.node
  const displayOperation = caseDetail?.trigger_operation || incident.invariant
  const displayOperator = caseDetail?.operator_id || incident.operator
  const riskText = formatRisk(displayRisk)
  const activeScenario = demoScenarios.find((scenario) => scenario.id === incident.scenarioId)
  const localTopology = useMemo(
    () =>
      selectDemoTopology({
        scenarioId: incident.scenarioId,
        segmentMode: incident.mode,
        shiftPhase: incident.phaseKey,
        riskControls,
        rangeDays: 30,
        linkCategories: [],
      }),
    [incident.mode, incident.phaseKey, incident.scenarioId, riskControls],
  )
  const localLinks = localTopology.links.slice(0, 4)
  const localNodeIds = new Set(localLinks.flatMap((link) => [link.from, link.to]))
  const localNodes = localTopology.nodes.filter((node) => localNodeIds.has(node.id)).slice(0, 6)
  const visibleRecords = records.length > 0 ? records : [...(caseDetail?.formal_verdict_records ?? [])].reverse()
  const operatorHistoryEntries = recordArray(operatorHistory, 'entries')
  const evidenceItems = recordArray(evidenceChecklist, 'items')
  const remediationEntries = recordArray(caseRemediations, 'items').length
    ? recordArray(caseRemediations, 'items')
    : recordArray(caseRemediations, 'remediations')
  const remediationAttempts = remediationEntries.length ? remediationEntries : recordArray(caseRemediations, 'attempts')
  const recheckEntries = recordArray(recheckHistory, 'entries')
  const visibleManualPermits = manualPermits.length > 0 ? manualPermits : caseDetail?.manual_permits ?? []
  const baseAudit = caseDetail?.audit_log.length ? caseDetail.audit_log.slice(-6).reverse() : demoAuditEvents
  const visibleAudit = [...localAudit, ...baseAudit]
  const permitBlocked = !manualPermit.work_order_number.trim() || permitState === 'saving'

  useEffect(() => {
    setStatus(incident.status)
    setReason('')
    setFormalVerdict('неопределённое')
    setFormalReason('')
    setFormalNote('')
    setConfidence(90)
    setRecords([])
    setOperatorHistory(null)
    setEvidenceChecklist(null)
    setCaseRemediations(null)
    setRecheckHistory(null)
    setComplianceDetailState(taktApiConfigured() ? 'loading' : 'local')
    setRemediationKind('attach_manual_permit')
    setRemediationNote('')
    setLatestAttemptId('')
    setRemediationState('idle')
    setRecheckState('idle')
    setLocalAudit([])
    setDecisionSaved(false)
    setDecisionState('idle')
    setReviewState('idle')
    setManualPermit(defaultManualPermit(incident.node, incident.invariant))
    setManualPermits([])
    setPermitState('idle')
    setDocumentPrepared(false)
    setSubmitState('idle')
    setBundleManifest(null)
    setDownloadedBundle(null)
    setBundleVerifyState('idle')
    setBundleVerifyResult('')
    setBundleState(taktApiConfigured() ? 'loading' : 'local')
    setBundleMessage('')
  }, [incident.id, incident.invariant, incident.node, incident.status])

  useEffect(() => {
    let cancelled = false
    if (!taktApiConfigured()) {
      setLoadState('local')
      return
    }
    setLoadState('loading')
    fetchCaseDetail(apiCaseId)
      .then((detail) => {
        if (cancelled) {
          return
        }
        setCaseDetail(detail)
        if (detail?.formal_verdict?.value) {
          setFormalVerdict(detail.formal_verdict.value)
        }
        setManualPermits(detail?.manual_permits ?? [])
        setLoadState('loaded')
      })
      .catch(() => {
        if (!cancelled) {
          setLoadState('error')
        }
      })
    return () => {
      cancelled = true
    }
  }, [apiCaseId])

  useEffect(() => {
    if (!taktApiConfigured()) {
      return
    }
    recordCaseViewed(apiCaseId, { reason: 'case detail opened', note: 'operator UI view' }).catch(() => {
      setLocalAudit((current) => [`${new Date().toLocaleTimeString('ru-RU')} API viewed action failed`, ...current])
    })
  }, [apiCaseId])

  useEffect(() => {
    let cancelled = false
    if (!taktApiConfigured()) {
      setBundleState('local')
      return
    }
    setBundleState('loading')
    fetchForensicBundleManifest(apiCaseId)
      .then((manifest) => {
        if (cancelled) {
          return
        }
        setBundleManifest(manifest)
        setBundleState(manifest ? 'ready' : 'local')
      })
      .catch(() => {
        if (!cancelled) {
          setBundleState('error')
          setBundleMessage('Не удалось получить манифест доказательного пакета.')
        }
      })
    return () => {
      cancelled = true
    }
  }, [apiCaseId])

  useEffect(() => {
    let cancelled = false
    if (!taktApiConfigured()) {
      setComplianceDetailState('local')
      return
    }
    setComplianceDetailState('loading')
    Promise.all([
      fetchOperatorActionHistory(apiCaseId),
      fetchCaseEvidenceChecklist(apiCaseId),
      fetchCaseRemediations(apiCaseId),
      fetchCaseRemediationRecheckHistory(apiCaseId),
    ])
      .then(([history, checklist, remediations, rechecks]) => {
        if (cancelled) {
          return
        }
        setOperatorHistory(history)
        setEvidenceChecklist(checklist)
        setCaseRemediations(remediations)
        setRecheckHistory(rechecks)
        setComplianceDetailState('loaded')
      })
      .catch(() => {
        if (!cancelled) {
          setComplianceDetailState('error')
        }
      })
    return () => {
      cancelled = true
    }
  }, [apiCaseId])

  async function refreshComplianceDetail() {
    if (!taktApiConfigured()) {
      return
    }
    const [history, checklist, remediations, rechecks] = await Promise.all([
      fetchOperatorActionHistory(apiCaseId),
      fetchCaseEvidenceChecklist(apiCaseId),
      fetchCaseRemediations(apiCaseId),
      fetchCaseRemediationRecheckHistory(apiCaseId),
    ])
    setOperatorHistory(history)
    setEvidenceChecklist(checklist)
    setCaseRemediations(remediations)
    setRecheckHistory(rechecks)
  }

  async function handleRemediationAttemptSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (remediationState === 'saving' || remediationNote.trim().length < 6) {
      return
    }
    setRemediationState('saving')
    try {
      const response = await recordCaseRemediationAttempt(apiCaseId, {
        kind: remediationKind,
        status: 'started',
        action: 'operator_recorded_remediation_attempt',
        note: remediationNote.trim(),
      })
      const attempt = response?.attempt
      if (typeof attempt === 'object' && attempt !== null && !Array.isArray(attempt)) {
        const attemptId = (attempt as Record<string, unknown>).attempt_id
        setLatestAttemptId(typeof attemptId === 'string' ? attemptId : '')
      }
      setRemediationState('saved')
      setLocalAudit((current) => [
        `${new Date().toLocaleTimeString('ru-RU')} устранение разрыва зафиксировано через API: ${remediationKindLabels[remediationKind] ?? remediationKind}`,
        ...current,
      ])
      await refreshComplianceDetail()
    } catch {
      setRemediationState('error')
    }
  }

  async function handleRemediationReadinessRecheck() {
    if (recheckState === 'saving' || !latestAttemptId) {
      return
    }
    setRecheckState('saving')
    try {
      await recheckCaseRemediationReadiness(apiCaseId, {
        attempt_id: latestAttemptId,
        note: remediationNote.trim() || 'оператор запросил повторную проверку готовности',
      })
      setRecheckState('saved')
      setLocalAudit((current) => [
        `${new Date().toLocaleTimeString('ru-RU')} готовность устранения разрыва повторно проверена через API`,
        ...current,
      ])
      await refreshComplianceDetail()
    } catch {
      setRecheckState('error')
    }
  }

  async function handleFormalVerdictSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (verdictBlocked) {
      return
    }
    setSubmitState('saving')
    try {
      const record = await sendFormalVerdictConfirmation(apiCaseId, {
        verdict: formalVerdict,
        confidence: confidence / 100,
        reason: formalReason.trim(),
        note: formalNote.trim(),
      })
      setRecords((current) => [record, ...current])
      setLocalAudit((current) => [
        taktApiConfigured()
          ? `${new Date().toLocaleTimeString('ru-RU')} формальный вердикт подтверждён через API: ${record.next}`
          : `${new Date().toLocaleTimeString('ru-RU')} локальный демо-вердикт NON-EVIDENCE, не серверная доказательность: ${record.next}`,
        ...current,
      ])
      setFormalVerdict(record.next)
      setSubmitState('saved')
    } catch {
      setSubmitState('error')
    }
  }

  async function handleDecisionSubmit() {
    if (blocked || decisionState === 'saving') {
      return
    }
    setDecisionState('saving')
    try {
      const apiStatus = apiStatusByLabel.get(status) ?? 'TRIAGE'
      if (taktApiConfigured()) {
        await submitCaseDecision(apiCaseId, {
          status: apiStatus,
          reason: reason.trim(),
        })
      }
      setDecisionSaved(true)
      setDecisionState('saved')
      setLocalAudit((current) => [
        taktApiConfigured()
          ? `${new Date().toLocaleTimeString('ru-RU')} решение оператора сохранено через API: ${apiStatus}`
          : `${new Date().toLocaleTimeString('ru-RU')} локальное демо-решение оператора NON-EVIDENCE, не серверная доказательность: ${apiStatus}`,
        ...current,
      ])
    } catch {
      setDecisionState('error')
    }
  }

  async function handleAdditionalReview() {
    if (reason.trim().length < 12 || reviewState === 'saving') {
      return
    }
    setReviewState('saving')
    try {
      if (taktApiConfigured()) {
        await requestAdditionalReview(apiCaseId, {
          reason: reason.trim(),
          note: `current_status=${apiStatusByLabel.get(status) ?? 'TRIAGE'}`,
        })
      }
      setReviewState('saved')
      setLocalAudit((current) => [
        taktApiConfigured()
          ? `${new Date().toLocaleTimeString('ru-RU')} дополнительная проверка запрошена через API`
          : `${new Date().toLocaleTimeString('ru-RU')} локальный демо-запрос дополнительной проверки NON-EVIDENCE, не серверная доказательность`,
        ...current,
      ])
    } catch {
      setReviewState('error')
    }
  }

  function updateManualPermitField<K extends keyof ManualPermitPayload>(key: K, value: ManualPermitPayload[K]) {
    setManualPermit((current) => ({ ...current, [key]: value }))
    setPermitState('idle')
  }

  async function handleManualPermitSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (permitBlocked) {
      return
    }
    setPermitState('saving')
    const payload: ManualPermitPayload = {
      ...manualPermit,
      work_order_number: manualPermit.work_order_number.trim(),
      asset_id: manualPermit.asset_id.trim() || displayAsset,
      operation: manualPermit.operation.trim() || displayOperation,
      action_class: manualPermit.action_class?.trim() ?? '',
      executor: manualPermit.executor.trim(),
      approver: manualPermit.approver.trim(),
      valid_from: manualPermit.valid_from.trim(),
      valid_to: manualPermit.valid_to.trim(),
      document_status: manualPermit.document_status.trim(),
      restrictions: manualPermit.restrictions?.trim() ?? '',
      note: manualPermit.note?.trim() ?? '',
    }
    try {
      if (taktApiConfigured()) {
        const response = await attachManualPermit(apiCaseId, payload)
        const permit = response?.permit
        if (permit && typeof permit === 'object' && !Array.isArray(permit)) {
          setManualPermits((current) => [permit as ManualPermitDetail, ...current])
        }
      } else {
        setManualPermits((current) => [
          {
            ...payload,
            permit_id: `local-${Date.now()}`,
            case_id: apiCaseId,
            actor: 'operator',
            created_at: new Date().toISOString(),
            action_class: payload.action_class ?? '',
            verdict: 'undetermined',
            confidence: 0.5,
            rationale: '',
            counterfactual: '',
            organizational_context_sha256: '',
            restrictions: payload.restrictions ?? '',
            note: payload.note ?? '',
          },
          ...current,
        ])
      }
      setPermitState('saved')
      setLocalAudit((current) => [
        taktApiConfigured()
          ? `${new Date().toLocaleTimeString('ru-RU')} ручной наряд прикреплён через API: ${payload.work_order_number}`
          : `${new Date().toLocaleTimeString('ru-RU')} локальный демо-наряд NON-EVIDENCE, не серверная доказательность: ${payload.work_order_number}`,
        ...current,
      ])
      setManualPermit(defaultManualPermit(displayAsset, displayOperation))
    } catch {
      setPermitState('error')
    }
  }

  function buildCaseDocument(): string {
    return [
      'NON-EVIDENCE LOCAL OPERATOR NOTE',
      'This file is not a forensic bundle, has no root hash, and must not be used as machine-verifiable evidence.',
      '',
      'Паспорт инцидента ТАКТ',
      `Инцидент: ${displayCaseId}`,
      `Сценарий: ${activeScenario?.title ?? incident.scenarioId}`,
      `Время: ${incident.time}`,
      `Актив: ${displayAsset}`,
      `Операция: ${displayOperation}`,
      `Оператор: ${displayOperator}`,
      `Рабочий статус: ${status}`,
      `Формальный вердикт: ${formalVerdict}`,
      `Индекс риска: ${riskText}`,
      `Заявка или наряд: ${incident.serviceDesk ?? 'не указан'}`,
      '',
      'Что произошло:',
      displayTitle,
      '',
      'Контрфактическое объяснение:',
      incident.serviceDesk
        ? `Событие считается ожидаемым при действующей заявке ${incident.serviceDesk}, совпадающем активе и подтверждении оператора.`
        : 'Для признания действия допустимым нужен действующий наряд или заявка с совпадающим активом, исполнителем, окном работ и утверждающим лицом.',
      '',
      'Аудиторский след:',
      ...visibleAudit,
    ].join('\n')
  }

  function exportLocalCaseDocument() {
    const text = buildCaseDocument()
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `non-evidence-local-case-note-${displayCaseId}.txt`
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
    setDocumentPrepared(true)
    setLocalAudit((current) => [`${new Date().toLocaleTimeString('ru-RU')} prepared non-evidence local operator note`, ...current])
  }

  async function exportForensicBundle() {
    if (!taktApiConfigured()) {
      exportLocalCaseDocument()
      setBundleState('local')
      setBundleMessage('Backend API не настроен. Скачанный файл является локальной операторской заметкой NON-EVIDENCE, а не forensic bundle.')
      return
    }
    setBundleState('loading')
    setBundleMessage('')
    try {
      const result = await downloadForensicBundle(apiCaseId)
      if (!result) {
        exportLocalCaseDocument()
        setBundleState('local')
        setBundleMessage('Backend API не настроен. Скачанный файл является локальной операторской заметкой NON-EVIDENCE, а не forensic bundle.')
        return
      }
      const url = URL.createObjectURL(result.blob)
      setDownloadedBundle(result.blob)
      setBundleVerifyState('idle')
      setBundleVerifyResult('')
      const link = document.createElement('a')
      link.href = url
      link.download = result.filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
      setDocumentPrepared(true)
      setBundleState('ready')
      setBundleMessage(
        `Доказательный ZIP-пакет выгружен. Root hash: ${result.rootHash || 'получен в манифесте'}, подпись: ${result.signatureStatus || 'статус не указан'}.`,
      )
      setLocalAudit((current) => [
        `${new Date().toLocaleTimeString('ru-RU')} выгружен доказательный ZIP-пакет`,
        ...current,
      ])
      const manifest = await fetchForensicBundleManifest(apiCaseId)
      setBundleManifest(manifest)
    } catch {
      setBundleState('error')
      setBundleMessage('Не удалось выгрузить доказательный пакет с сервера данных.')
    }
  }

  async function verifyDownloadedForensicBundle() {
    if (!downloadedBundle || bundleVerifyState === 'verifying') {
      return
    }
    setBundleVerifyState('verifying')
    setBundleVerifyResult('')
    try {
      const result = await verifyForensicBundle(downloadedBundle)
      const rootHash = result?.root_hash_sha256 ?? result?.root_hash ?? result?.manifest_root_hash ?? ''
      const status = result?.ok ?? result?.valid ?? result?.status ?? 'verified'
      setBundleVerifyState('verified')
      setBundleVerifyResult(`verify=${String(status)}${rootHash ? ` root=${String(rootHash)}` : ''}`)
      setLocalAudit((current) => [
        `${new Date().toLocaleTimeString('ru-RU')} forensic ZIP verified through /forensic-bundle/verify`,
        ...current,
      ])
    } catch {
      setBundleVerifyState('error')
      setBundleVerifyResult('Forensic ZIP verification failed.')
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Карточка инцидента</h1>
          <p className="mt-1 font-mono text-[16px] text-[var(--fg-1)]">{displayCaseId}</p>
          <p className="mt-2 text-[13px] text-[var(--fg-2)]">{displayTitle}</p>
          <p className="mt-1 text-[12px] text-[var(--fg-3)]">
            Актив: {displayAsset} · Время: {incident.time} · Операция: {displayOperation} · Оператор: {displayOperator}
          </p>
          {loadState === 'error' ? (
            <p className="mt-2 text-[12px] text-[var(--amber-1)]">Сервер данных недоступен, показан локальный демонстрационный сценарий.</p>
          ) : null}
        </div>
        <RiskBadge value={displayRisk} />
      </div>

      <div className="flex flex-wrap gap-2" role="group" aria-label="Смена статуса инцидента">
        {statusLabels.map((label) => (
          <Button key={label} variant={status === label ? 'primary' : 'ghost'} onClick={() => setStatus(label)}>
            {label}
          </Button>
        ))}
      </div>

      <div className="flex flex-wrap gap-2 text-[12px]">
        <span className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] px-2 py-1 text-[var(--fg-2)]">
          Сценарий: {activeScenario?.title ?? incident.scenarioId}
        </span>
        <span className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] px-2 py-1 text-[var(--fg-2)]">
          Заявка или наряд: {incident.serviceDesk ?? 'не указан'}
        </span>
        <span className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] px-2 py-1 text-[var(--fg-2)]">
          Контур: только наблюдение и классификация
        </span>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {[
          ['Что произошло', displayTitle],
          ['Почему это необычно', `Проверяется инвариант «${displayOperation}» для фазы «${incident.phase}», текущий статус: «${status}».`],
          ['Рекомендуемое действие', 'Сверить журнал телеметрии, сменный наряд, заявку службы сопровождения и вручную классифицировать инцидент.'],
          ['Условия нормальности', incident.serviceDesk ? `Есть связанная заявка ${incident.serviceDesk}; требуется подтверждение оператора.` : 'Нужны связанная заявка, окно обслуживания и стабильный интервал опроса.'],
        ].map(([title, text]) => (
          <section key={title} className="takt-card p-3">
            <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">{title}</h2>
            <p className="mt-2 text-[13px] text-[var(--fg-2)]">{text}</p>
          </section>
        ))}
      </div>

      <section className="takt-card p-4">
        <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Локальный граф инцидента</h2>
        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3">
            <div className="text-[12px] text-[var(--fg-3)]">Ближайшие узлы</div>
            <div className="mt-2 flex flex-wrap gap-2">
              {localNodes.map((node) => (
                <span key={node.id} className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] px-2 py-1 text-[12px] text-[var(--fg-2)]">
                  {node.label}
                </span>
              ))}
              {localNodes.length === 0 ? <span className="text-[12px] text-[var(--fg-3)]">Узлы не найдены</span> : null}
            </div>
          </div>
          <div className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3">
            <div className="text-[12px] text-[var(--fg-3)]">Связи до двух переходов</div>
            <div className="mt-2 flex flex-col gap-2">
              {localLinks.map((link) => (
                <p key={link.id} className="text-[12px] text-[var(--fg-2)]">
                  <b className="text-[var(--fg-1)]">{link.label}</b> · {link.detail}
                </p>
              ))}
              {localLinks.length === 0 ? <span className="text-[12px] text-[var(--fg-3)]">Связи не найдены</span> : null}
            </div>
          </div>
        </div>
      </section>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="takt-card p-4">
          <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Ход событий</h2>
          <ol className="mt-3 list-decimal space-y-2 pl-5 font-mono text-[12px] text-[var(--fg-2)]">
            <li>{incident.time} событие получено из демо-эмулятора теплоэнергетики</li>
            <li>Узел: {displayAsset}</li>
            <li>Инвариант: {displayOperation}; индекс риска = {riskText}</li>
            <li>Оператор {displayOperator} открыл карточку для ручной классификации</li>
          </ol>
          <div className="mt-4 border-t border-[var(--line)] pt-4">
            <label className="text-[12px] text-[var(--fg-2)]" htmlFor="expected-reason">
              Обоснование оператора
            </label>
            <textarea
              id="expected-reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              className="mt-2 min-h-24 w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3 text-[13px] text-[var(--fg-1)] takt-focus-ring"
              placeholder="Обязательно для любого решения оператора"
            />
            <Button
              data-testid="case-decision-submit"
              disabled={blocked || decisionState === 'saving'}
              onClick={() => {
                void handleDecisionSubmit()
              }}
            >
              Зафиксировать решение оператора
            </Button>
            {blocked ? <p className="mt-2 text-[12px] text-[var(--amber-1)]">Нужно текстовое обоснование. Авто-классификация запрещена.</p> : null}
            {decisionSaved ? <p className="mt-2 text-[12px] text-[var(--teal-1)]">Решение добавлено в локальный аудиторский след.</p> : null}
            <Button
              className="mt-3"
              data-testid="case-additional-review"
              variant="ghost"
              disabled={reason.trim().length < 12 || reviewState === 'saving'}
              onClick={() => {
                void handleAdditionalReview()
              }}
            >
              Передать на дополнительную проверку
            </Button>
            {reviewState === 'saved' ? <p className="mt-2 text-[12px] text-[var(--teal-1)]">Запрос на дополнительную проверку зафиксирован через API.</p> : null}
            {reviewState === 'error' ? <p className="mt-2 text-[12px] text-[var(--risk-high)]">Не удалось зафиксировать дополнительную проверку через API.</p> : null}
          </div>
        </section>
        <div className="flex flex-col gap-4">
          <aside className="takt-card p-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-[var(--teal-1)]" strokeWidth={1.7} aria-hidden />
              <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Режим соответствия требованиям</h2>
            </div>
            <form className="mt-3 flex flex-col gap-3" onSubmit={handleFormalVerdictSubmit}>
              <fieldset>
                <legend className="text-[12px] text-[var(--fg-2)]">Формальный вердикт</legend>
                <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-3 xl:grid-cols-1" role="group" aria-label="Формальный вердикт">
                  {verdictLabels.map((label) => (
                    <button
                      key={label}
                      type="button"
                      onClick={() => setFormalVerdict(label)}
                      className={`rounded-takt border px-3 py-2 text-left text-[13px] takt-focus-ring ${
                        formalVerdict === label
                          ? `${verdictTone[label]} bg-[var(--bg-2)]`
                          : 'border-[var(--line)] text-[var(--fg-2)] hover:bg-[var(--bg-2)]'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </fieldset>

              <label className="text-[12px] text-[var(--fg-2)]" htmlFor="formal-confidence">
                Уверенность: <span className="font-mono text-[var(--fg-1)]">{confidence}%</span>
              </label>
              <input
                id="formal-confidence"
                type="range"
                min="0"
                max="100"
                step="5"
                value={confidence}
                onChange={(event) => setConfidence(Number(event.target.value))}
                className="w-full accent-[var(--teal-1)]"
              />

              <label className="text-[12px] text-[var(--fg-2)]" htmlFor="formal-reason">
                Основание подтверждения
              </label>
              <textarea
                id="formal-reason"
                value={formalReason}
                onChange={(event) => setFormalReason(event.target.value)}
                className="min-h-24 w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3 text-[13px] text-[var(--fg-1)] takt-focus-ring"
                placeholder="Например: начальник смены подтвердил отсутствие действующего наряда"
              />

              <label className="text-[12px] text-[var(--fg-2)]" htmlFor="formal-note">
                Примечание
              </label>
              <input
                id="formal-note"
                value={formalNote}
                onChange={(event) => setFormalNote(event.target.value)}
                className="w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring"
                placeholder="Номер служебной записи или комментарий"
              />

              <Button
                className="inline-flex items-center justify-center gap-2"
                data-testid="case-formal-verdict-submit"
                disabled={verdictBlocked}
                type="submit"
              >
                <CheckCircle2 className="h-4 w-4" strokeWidth={1.7} aria-hidden />
                Подтвердить вердикт
              </Button>
              {formalReason.trim().length < 12 ? (
                <p className="text-[12px] text-[var(--amber-1)]">Нужно развёрнутое основание для аудиторского следа.</p>
              ) : null}
              {submitState === 'saved' ? (
                <p className="text-[12px] text-[var(--teal-1)]">Вердикт зафиксирован в истории подтверждений.</p>
              ) : null}
              {submitState === 'error' ? (
                <p className="text-[12px] text-[var(--risk-high)]">Не удалось отправить подтверждение на сервер данных.</p>
              ) : null}
            </form>
          </aside>

          <aside className="takt-card p-4">
            <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Ручной наряд</h2>
            <form className="mt-3 flex flex-col gap-3" onSubmit={handleManualPermitSubmit}>
              <label className="text-[12px] text-[var(--fg-2)]" htmlFor="permit-work-order">
                Номер наряда
              </label>
              <input
                id="permit-work-order"
                value={manualPermit.work_order_number}
                onChange={(event) => updateManualPermitField('work_order_number', event.target.value)}
                className="w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring"
                placeholder="WO-2026-0001"
              />

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-1">
                <label className="text-[12px] text-[var(--fg-2)]" htmlFor="permit-asset">
                  Актив
                  <input
                    id="permit-asset"
                    value={manualPermit.asset_id}
                    onChange={(event) => updateManualPermitField('asset_id', event.target.value)}
                    className="mt-1 w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring"
                  />
                </label>
                <label className="text-[12px] text-[var(--fg-2)]" htmlFor="permit-operation">
                  Операция
                  <input
                    id="permit-operation"
                    value={manualPermit.operation}
                    onChange={(event) => updateManualPermitField('operation', event.target.value)}
                    className="mt-1 w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring"
                  />
                </label>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-1">
                <label className="text-[12px] text-[var(--fg-2)]" htmlFor="permit-executor">
                  Исполнитель
                  <input
                    id="permit-executor"
                    value={manualPermit.executor}
                    onChange={(event) => updateManualPermitField('executor', event.target.value)}
                    className="mt-1 w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring"
                  />
                </label>
                <label className="text-[12px] text-[var(--fg-2)]" htmlFor="permit-approver">
                  Утвердил
                  <input
                    id="permit-approver"
                    value={manualPermit.approver}
                    onChange={(event) => updateManualPermitField('approver', event.target.value)}
                    className="mt-1 w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring"
                  />
                </label>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-1">
                <label className="text-[12px] text-[var(--fg-2)]" htmlFor="permit-valid-from">
                  Действует с
                  <input
                    id="permit-valid-from"
                    type="datetime-local"
                    value={manualPermit.valid_from}
                    onChange={(event) => updateManualPermitField('valid_from', event.target.value)}
                    className="mt-1 w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring"
                  />
                </label>
                <label className="text-[12px] text-[var(--fg-2)]" htmlFor="permit-valid-to">
                  Действует до
                  <input
                    id="permit-valid-to"
                    type="datetime-local"
                    value={manualPermit.valid_to}
                    onChange={(event) => updateManualPermitField('valid_to', event.target.value)}
                    className="mt-1 w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[13px] text-[var(--fg-1)] takt-focus-ring"
                  />
                </label>
              </div>

              <label className="text-[12px] text-[var(--fg-2)]" htmlFor="permit-note">
                Примечание
              </label>
              <textarea
                id="permit-note"
                value={manualPermit.note}
                onChange={(event) => updateManualPermitField('note', event.target.value)}
                className="min-h-20 w-full rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3 text-[13px] text-[var(--fg-1)] takt-focus-ring"
                placeholder="Контекст допуска и подтверждения"
              />

              <Button
                className="inline-flex items-center justify-center gap-2"
                data-testid="case-manual-permit-submit"
                disabled={permitBlocked}
                type="submit"
              >
                <FileCheck2 className="h-4 w-4" strokeWidth={1.7} aria-hidden />
                Прикрепить наряд
              </Button>
              {permitState === 'saved' ? <p className="text-[12px] text-[var(--teal-1)]">Наряд прикреплён к делу через API.</p> : null}
              {permitState === 'error' ? <p className="text-[12px] text-[var(--risk-high)]">Не удалось прикрепить наряд к делу.</p> : null}
            </form>

            <div className="mt-4 border-t border-[var(--line)] pt-3">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Прикреплённые наряды</h3>
              <ol className="mt-2 space-y-2 text-[12px] text-[var(--fg-2)]">
                {visibleManualPermits.map((permit) => (
                  <li key={permit.permit_id || permit.work_order_number} className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-2">
                    <div className="font-mono text-[var(--fg-1)]">{permit.work_order_number}</div>
                    <div>{permit.asset_id || displayAsset} · {permit.operation || displayOperation}</div>
                    <div>Вердикт: {permit.verdict}; уверенность {Math.round(permit.confidence * 100)}%</div>
                    {permit.organizational_context_sha256 ? (
                      <div className="break-all font-mono text-[var(--fg-3)]">sha256={permit.organizational_context_sha256}</div>
                    ) : null}
                  </li>
                ))}
                {visibleManualPermits.length === 0 ? <li>Наряды ещё не прикреплены.</li> : null}
              </ol>
            </div>
          </aside>
          <aside className="takt-card p-4">
            <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Аудиторский след</h2>
            <div className="mt-3 rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3 text-[12px] text-[var(--fg-2)]">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Доказательный пакет</h3>
              {bundleManifest ? (
                <dl className="mt-2 grid gap-1">
                  <div>
                    <dt className="text-[var(--fg-3)]">Пакет</dt>
                    <dd className="font-mono text-[var(--fg-1)]">{bundleManifest.package_id}</dd>
                  </div>
                  <div>
                    <dt className="text-[var(--fg-3)]">Корневой хэш</dt>
                    <dd className="break-all font-mono text-[var(--fg-1)]">{bundleManifest.root_hash_sha256}</dd>
                  </div>
                  <div>
                    <dt className="text-[var(--fg-3)]">Статус подписи</dt>
                    <dd>{bundleManifest.signature_status}</dd>
                  </div>
                  <div>
                    <dt className="text-[var(--fg-3)]">Метка пригодности</dt>
                    <dd>{bundleManifest.suitability_label}</dd>
                  </div>
                  <div>
                    <dt className="text-[var(--fg-3)]">Элементы</dt>
                    <dd>{bundleManifest.items.length}</dd>
                  </div>
                </dl>
              ) : (
                <p className="mt-2">
                  {bundleState === 'loading'
                    ? 'Получение манифеста...'
                    : bundleState === 'local'
                      ? 'Backend API не настроен. Доступна только локальная операторская заметка NON-EVIDENCE.'
                      : 'Манифест доказательного пакета недоступен.'}
                </p>
              )}
              {bundleMessage ? <p className="mt-2 text-[var(--amber-1)]">{bundleMessage}</p> : null}
            </div>
            <div className="mt-3 rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3 text-[12px] text-[var(--fg-2)]">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">API-детали соответствия</h3>
                <span className="font-mono text-[var(--fg-3)]">{displayState(complianceDetailState)}</span>
              </div>
              <dl className="mt-2 grid gap-2">
                <div>
                  <dt className="text-[var(--fg-3)]">История действий оператора</dt>
                  <dd className="font-mono text-[var(--fg-1)]">{operatorHistoryEntries.length}</dd>
                </div>
                <div>
                  <dt className="text-[var(--fg-3)]">Чек-лист доказательности</dt>
                  <dd className="font-mono text-[var(--fg-1)]">
                    {evidenceChecklist ? `${String(evidenceChecklist.ready ?? 'нет данных')} / ${evidenceItems.length} проверок` : 'нет данных'}
                  </dd>
                </div>
                <div>
                  <dt className="text-[var(--fg-3)]">Устранения разрывов</dt>
                  <dd className="font-mono text-[var(--fg-1)]">{remediationAttempts.length}</dd>
                </div>
                <div>
                  <dt className="text-[var(--fg-3)]">Повторные проверки готовности</dt>
                  <dd className="font-mono text-[var(--fg-1)]">{recheckEntries.length}</dd>
                </div>
              </dl>
              <form className="mt-3 grid gap-2" onSubmit={handleRemediationAttemptSubmit}>
                <label className="grid gap-1 text-[12px] text-[var(--fg-2)]" htmlFor="remediation-kind">
                  Тип устранения разрыва
                  <select
                    id="remediation-kind"
                    value={remediationKind}
                    onChange={(event) => setRemediationKind(event.target.value)}
                    className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 text-[12px] text-[var(--fg-1)] takt-focus-ring"
                  >
                    {Object.entries(remediationKindLabels).map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="grid gap-1 text-[12px] text-[var(--fg-2)]" htmlFor="remediation-note">
                  Заметка оператора
                  <textarea
                    id="remediation-note"
                    value={remediationNote}
                    onChange={(event) => setRemediationNote(event.target.value)}
                    className="min-h-16 rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-2 text-[12px] text-[var(--fg-1)] takt-focus-ring"
                    placeholder="Что сделано для закрытия разрыва доказательности"
                  />
                </label>
                <div className="flex flex-wrap gap-2">
                  <Button
                    data-testid="case-remediation-attempt-submit"
                    disabled={remediationState === 'saving' || remediationNote.trim().length < 6}
                    type="submit"
                  >
                    {remediationState === 'saving' ? 'Фиксируется' : 'Зафиксировать устранение разрыва'}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    disabled={recheckState === 'saving' || !latestAttemptId}
                    onClick={() => {
                      void handleRemediationReadinessRecheck()
                    }}
                  >
                    {recheckState === 'saving' ? 'Проверяется' : 'Повторно проверить готовность'}
                  </Button>
                </div>
                {latestAttemptId ? <p className="font-mono text-[12px] text-[var(--fg-3)]">ID попытки: {latestAttemptId}</p> : null}
                {remediationState === 'saved' ? <p className="text-[12px] text-[var(--teal-1)]">Устранение разрыва зафиксировано через API.</p> : null}
                {remediationState === 'error' ? <p className="text-[12px] text-[var(--risk-high)]">Не удалось зафиксировать устранение разрыва.</p> : null}
                {recheckState === 'saved' ? <p className="text-[12px] text-[var(--teal-1)]">Повторная проверка готовности зафиксирована через API.</p> : null}
                {recheckState === 'error' ? <p className="text-[12px] text-[var(--risk-high)]">Не удалось повторно проверить готовность.</p> : null}
              </form>
              {evidenceItems.length > 0 ? (
                <ol className="mt-2 space-y-1">
                  {evidenceItems.slice(0, 4).map((item, index) => (
                    <li key={`${String(item.code ?? item.label ?? 'проверка')}-${index}`}>
                      {String(item.code ?? item.label ?? 'проверка')}: {String(item.ok ?? item.status ?? 'нет данных')}
                    </li>
                  ))}
                </ol>
              ) : null}
            </div>
            <ol className="mt-3 space-y-2 text-[12px] text-[var(--fg-2)]">
              {visibleRecords.map((record) => (
                <li key={`${record.ts}-${record.next}`}>
                  {new Intl.DateTimeFormat('ru-RU', { timeStyle: 'medium' }).format(new Date(record.ts))}{' '}
                  подтверждён вердикт «{record.next}», уверенность {Math.round(record.score * 100)}%
                </li>
              ))}
              {visibleAudit.map((event) => <li key={event}>{event}</li>)}
            </ol>
            <Button
              className="mt-4 inline-flex items-center gap-2"
              data-testid="case-forensic-download"
              variant="ghost"
              onClick={exportForensicBundle}
              disabled={bundleState === 'loading'}
            >
              <FileCheck2 className="h-4 w-4" strokeWidth={1.7} aria-hidden />
              Скачать серверный forensic ZIP
            </Button>
            <Button
              className="mt-2 inline-flex items-center gap-2"
              data-testid="case-forensic-verify"
              variant="ghost"
              onClick={() => {
                void verifyDownloadedForensicBundle()
              }}
              disabled={!downloadedBundle || bundleVerifyState === 'verifying'}
            >
              <FileCheck2 className="h-4 w-4" strokeWidth={1.7} aria-hidden />
              Проверить серверный forensic ZIP
            </Button>
            {bundleVerifyResult ? <p className="mt-2 break-all text-[12px] text-[var(--fg-2)]">{bundleVerifyResult}</p> : null}
            <Button
              className="mt-2 inline-flex items-center gap-2"
              variant="ghost"
              onClick={exportLocalCaseDocument}
            >
              <FileCheck2 className="h-4 w-4" strokeWidth={1.7} aria-hidden />
              Локальная заметка NON-EVIDENCE
            </Button>
            <Button
              className="mt-2 inline-flex items-center gap-2"
              variant="ghost"
              onClick={() => {
                setLocalAudit((current) => [`${new Date().toLocaleTimeString('ru-RU')} открыт диалог печати/PDF для локальной операторской заметки NON-EVIDENCE`, ...current])
                window.print()
              }}
            >
              <FileCheck2 className="h-4 w-4" strokeWidth={1.7} aria-hidden />
              Печать/PDF NON-EVIDENCE
            </Button>
            {documentPrepared ? <p className="mt-2 text-[12px] text-[var(--teal-1)]">Локальная заметка NON-EVIDENCE подготовлена. Для машинно-проверяемой доказательности используйте серверный forensic ZIP.</p> : null}
          </aside>
        </div>
      </div>

      <p className="text-[12px] text-[var(--fg-3)]">
        Человек в контуре: система только объясняет и подсвечивает риск, решение принимает оператор.
      </p>
    </div>
  )
}
