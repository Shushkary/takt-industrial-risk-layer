import { useEffect, useState } from 'react'
import { Button } from '../components/ui/Button'
import {
  fetchComplianceMode,
  fetchDataQualityReport,
  fetchAuditEngagements,
  fetchForensicReadiness,
  ingestEventBatch,
  taktApiConfigured,
  verifyCaseAuditLedger,
  verifyOperationLedger,
  type AuditEngagementsResponse,
  type AuditLedgerVerifyResponse,
  type ComplianceModeResponse,
  type DataQualityReportResponse,
  type ForensicReadinessResponse,
} from '../app/taktApi'
import { demoAuditEvents, heatEnergyDemoEventBatch } from '../demo'

function numberField(record: Record<string, unknown> | null, key: string): number | string {
  const value = record?.[key]
  return typeof value === 'number' ? value : 'нет данных'
}

function nestedRecord(record: Record<string, unknown> | null, key: string): Record<string, unknown> | null {
  const value = record?.[key]
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null
}

function complianceEnabled(mode: ComplianceModeResponse | null): boolean {
  return mode?.compliance_enabled === true
}

function statusText(value: unknown): string {
  if (value === true) {
    return 'да'
  }
  if (value === false) {
    return 'нет'
  }
  if (value === undefined || value === null || value === 'loaded') {
    return value === 'loaded' ? 'загружено' : 'нет данных'
  }
  return String(value)
}

export function SettingsAudit() {
  const [now, setNow] = useState(() => new Date())
  const [localAudit, setLocalAudit] = useState<string[]>([])
  const [reportText, setReportText] = useState('')
  const [complianceMode, setComplianceMode] = useState<ComplianceModeResponse | null>(null)
  const [dataQuality, setDataQuality] = useState<DataQualityReportResponse | null>(null)
  const [forensicReadiness, setForensicReadiness] = useState<ForensicReadinessResponse | null>(null)
  const [auditEngagements, setAuditEngagements] = useState<AuditEngagementsResponse | null>(null)
  const [operationLedger, setOperationLedger] = useState<AuditLedgerVerifyResponse | null>(null)
  const [caseLedger, setCaseLedger] = useState<AuditLedgerVerifyResponse | null>(null)
  const [caseLedgerId, setCaseLedgerId] = useState('')
  const [ledgerState, setLedgerState] = useState<'idle' | 'loading' | 'loaded' | 'error'>('idle')
  const [ledgerMessage, setLedgerMessage] = useState('')
  const [demoIngestState, setDemoIngestState] = useState<'idle' | 'loading' | 'loaded' | 'error'>('idle')
  const [demoIngestResult, setDemoIngestResult] = useState('')
  const [complianceState, setComplianceState] = useState<'local' | 'loading' | 'loaded' | 'error'>(
    taktApiConfigured() ? 'loading' : 'local',
  )
  const auditRows = [...localAudit, ...demoAuditEvents]
  const productBoundary = nestedRecord(complianceMode, 'product_boundary')
  const readiness = nestedRecord(complianceMode, 'readiness')
  const localReportBlocked = complianceEnabled(complianceMode)
  const operationLedgerOk = operationLedger ? statusText(operationLedger.ok ?? operationLedger.valid ?? operationLedger.status ?? 'loaded') : 'нет данных'
  const caseLedgerOk = caseLedger ? statusText(caseLedger.ok ?? caseLedger.valid ?? caseLedger.status ?? 'loaded') : 'нет данных'

  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 5000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    let cancelled = false
    if (!taktApiConfigured()) {
      setComplianceState('local')
      setComplianceMode(null)
      setDataQuality(null)
      setForensicReadiness(null)
      return
    }
    setComplianceState('loading')
    Promise.all([fetchComplianceMode(), fetchDataQualityReport(), fetchForensicReadiness(), fetchAuditEngagements()])
      .then(([mode, quality, forensic, engagements]) => {
        if (cancelled) {
          return
        }
        setComplianceMode(mode)
        setDataQuality(quality)
        setForensicReadiness(forensic)
        setAuditEngagements(engagements)
        setComplianceState('loaded')
      })
      .catch(() => {
        if (!cancelled) {
          setComplianceMode(null)
          setDataQuality(null)
          setForensicReadiness(null)
          setAuditEngagements(null)
          setComplianceState('error')
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  function confirmAirGap() {
    setLocalAudit((current) => [
      `${new Date().toLocaleTimeString('ru-RU')} локальное подтверждение изоляции без доказательной силы; для доказательности используйте серверную аудиторскую цепочку`,
      ...current,
    ])
  }

  function buildReport(): string {
    return [
      'ЛОКАЛЬНЫЙ ОТЧЁТ ИНТЕРФЕЙСА — БЕЗ ДОКАЗАТЕЛЬНОЙ СИЛЫ',
      'Этот отчёт сформирован в браузере и не является машинно-проверяемым доказательным артефактом.',
      '',
      'Отчёт настроек и аудита ТАКТ',
      `Время проверки: ${now.toLocaleString('ru-RU')}`,
      'Исходящие соединения: 0',
      'Управление пользователями: только просмотр',
      'Контур: изолированный, без активного управления оборудованием',
      '',
      'Аудиторский след:',
      ...auditRows,
    ].join('\n')
  }

  function prepareReport() {
    if (localReportBlocked) {
      setReportText('ЛОКАЛЬНЫЙ ОТЧЁТ ИНТЕРФЕЙСА — БЕЗ ДОКАЗАТЕЛЬНОЙ СИЛЫ\nНормативный режим блокирует локальные отчёты настроек. Для доказательности используйте серверную проверку цепочек, готовность доказательного пакета и программный интерфейс аудиторских проверок.')
      return
    }
    setReportText(buildReport())
  }

  async function verifyAuditLedgers() {
    if (!taktApiConfigured()) {
      setLedgerState('error')
      setLedgerMessage('API не настроен. Проверка цепочек требует серверного интерфейса аудита.')
      return
    }
    setLedgerState('loading')
    setLedgerMessage('')
    try {
      const [operationResult, caseResult] = await Promise.all([
        verifyOperationLedger(''),
        caseLedgerId.trim() ? verifyCaseAuditLedger(caseLedgerId.trim()) : Promise.resolve(null),
      ])
      setOperationLedger(operationResult)
      setCaseLedger(caseResult)
      setLedgerState('loaded')
      setLedgerMessage(caseLedgerId.trim() ? 'Цепочка операций и выбранного кейса проверены через API.' : 'Цепочка операций проверена через API.')
      setLocalAudit((current) => [
        `${new Date().toLocaleTimeString('ru-RU')} цепочка аудита проверена через API`,
        ...current,
      ])
    } catch (error) {
      setLedgerState('error')
      setLedgerMessage(error instanceof Error ? error.message : 'Проверка цепочки не выполнена.')
    }
  }

  async function ingestHeatEnergyDemoEvents() {
    if (!taktApiConfigured()) {
      setDemoIngestState('error')
      setDemoIngestResult('API не настроен. Для загрузки демо-событий задайте VITE_TAKT_API_BASE_URL.')
      return
    }
    setDemoIngestState('loading')
    setDemoIngestResult('')
    try {
      const response = await ingestEventBatch(heatEnergyDemoEventBatch)
      const count = response?.count ?? 0
      setDemoIngestState('loaded')
      setDemoIngestResult(`Через /events/batch загружено наблюдений теплоэнергетики: ${count}.`)
      setLocalAudit((current) => [
        `${new Date().toLocaleTimeString('ru-RU')} через API загружено демо-наблюдений: ${count}; оператор остается финальным лицом принятия решения`,
        ...current,
      ])
    } catch (error) {
      setDemoIngestState('error')
      setDemoIngestResult(error instanceof Error ? error.message : 'Загрузка демо-событий не выполнена.')
    }
  }

  function exportReport() {
    if (localReportBlocked) {
      setReportText('ЛОКАЛЬНЫЙ ОТЧЁТ ИНТЕРФЕЙСА — БЕЗ ДОКАЗАТЕЛЬНОЙ СИЛЫ\nНормативный режим блокирует локальные отчёты настроек. Для доказательности используйте серверную проверку цепочек, готовность доказательного пакета и программный интерфейс аудиторских проверок.')
      return
    }
    const text = reportText || buildReport()
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

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">Настройки и аудит</h1>
      <p className="max-w-[72ch] text-[13px] text-[var(--fg-2)]">
        Административный экран для просмотра состава поставки, версий модулей, журнала действий и подтверждения изоляции контура теплоэнергетики.
      </p>
      <div className="grid gap-3 md:grid-cols-3">
        <article className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
          <h2 className="text-[13px] font-semibold">Состав поставки</h2>
          <p className="mt-2 text-[12px] text-[var(--fg-2)]">АРМ оператора 1.0.0 · ведомость компонентов · контрольная сумма совпадает</p>
        </article>
        <article className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
          <h2 className="text-[13px] font-semibold">Изолированный контур</h2>
          <p className="mt-2 text-[12px] text-[var(--fg-2)]">Исходящие соединения: 0 · источники: промышленный протокол обмена, журнал переходного сервера, архив теплосети</p>
          <p className="mt-1 font-mono text-[12px] text-[var(--teal-1)]">Обновлено: {now.toLocaleTimeString('ru-RU')}</p>
        </article>
        <article className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
          <h2 className="text-[13px] font-semibold">Пользователи</h2>
          <p className="mt-2 text-[12px] text-[var(--fg-2)]">Просмотр: 14 учётных записей, изменения выполняются вне интерфейса</p>
        </article>
      </div>
      <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-[13px] font-semibold">Нормативный режим на сервере</h2>
          <span className="font-mono text-[12px] text-[var(--fg-3)]">
            {complianceState === 'loaded'
              ? '/compliance/mode'
              : complianceState === 'loading'
                ? 'загружается'
                : complianceState === 'error'
                  ? 'недоступен'
                  : 'локальное демо'}
          </span>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <article className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3">
            <h3 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Граница продукта</h3>
            <dl className="mt-2 grid gap-1 text-[12px] text-[var(--fg-2)]">
              <div><dt>Нормативный режим</dt><dd>{statusText(complianceMode?.compliance_enabled)}</dd></div>
              <div><dt>Активное управление</dt><dd>{statusText(productBoundary?.has_active_control)}</dd></div>
              <div><dt>Финальное решение оператора</dt><dd>{statusText(productBoundary?.requires_operator_final_decision)}</dd></div>
            </dl>
          </article>
          <article className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3">
            <h3 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Качество данных</h3>
            <dl className="mt-2 grid gap-1 text-[12px] text-[var(--fg-2)]">
              <div><dt>Всего кейсов</dt><dd>{numberField(dataQuality, 'total_cases')}</dd></div>
              <div><dt>Открытые кейсы</dt><dd>{numberField(dataQuality, 'open_cases')}</dd></div>
              <div><dt>Без ручного наряда</dt><dd>{numberField(dataQuality, 'cases_without_manual_permit')}</dd></div>
              <div><dt>Высокий риск без решения</dt><dd>{numberField(dataQuality, 'high_risk_without_decision')}</dd></div>
            </dl>
          </article>
          <article className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] p-3">
            <h3 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Готовность доказательных пакетов</h3>
            <dl className="mt-2 grid gap-1 text-[12px] text-[var(--fg-2)]">
              <div><dt>Готово</dt><dd>{numberField(forensicReadiness, 'ready_cases')}</dd></div>
              <div><dt>Не готово</dt><dd>{numberField(forensicReadiness, 'not_ready_cases')}</dd></div>
              <div><dt>Всего по режиму</dt><dd>{numberField(readiness, 'total_cases')}</dd></div>
              <div><dt>Не готово по режиму</dt><dd>{numberField(readiness, 'not_ready_cases')}</dd></div>
            </dl>
          </article>
        </div>
      </section>
      <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-[13px] font-semibold">Проверка аудиторских цепочек</h2>
            <p className="mt-1 max-w-[72ch] text-[12px] text-[var(--fg-2)]">
              Проверяет цепочки операций и кейсов через серверный интерфейс. Локальные отчёты интерфейса остаются без доказательной силы.
            </p>
          </div>
          <span className="font-mono text-[12px] text-[var(--fg-3)]">
            проверки: {auditEngagements?.length ?? 'нет данных'}
          </span>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-[1fr_auto]">
          <label className="grid gap-1 text-[12px] text-[var(--fg-2)]">
            ID кейса для проверки цепочки
            <input
              className="rounded-takt border border-[var(--line)] bg-[var(--bg-0)] px-3 py-2 font-mono text-[12px] text-[var(--fg-1)] outline-none takt-focus-ring"
              value={caseLedgerId}
              onChange={(event) => setCaseLedgerId(event.target.value)}
              placeholder="необязательный case_id"
            />
          </label>
          <div className="flex items-end">
            <Button onClick={verifyAuditLedgers} disabled={ledgerState === 'loading'}>
              {ledgerState === 'loading' ? 'Проверяется' : 'Проверить цепочки'}
            </Button>
          </div>
        </div>
        <dl className="mt-3 grid gap-2 text-[12px] text-[var(--fg-2)] md:grid-cols-3">
          <div><dt>Цепочка операций</dt><dd className="font-mono">{operationLedgerOk}</dd></div>
          <div><dt>Цепочка кейса</dt><dd className="font-mono">{caseLedgerOk}</dd></div>
          <div><dt>Статус</dt><dd>{ledgerState === 'idle' ? 'готово к API-проверке' : ledgerMessage}</dd></div>
        </dl>
      </section>
      <section className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-[13px] font-semibold">API-загрузка демо-наблюдений</h2>
            <p className="mt-1 max-w-[72ch] text-[12px] text-[var(--fg-2)]">
              Загружает наблюдения московской теплоэнергетики в backend через /events/batch. Сценарий передает только входную телеметрию,
              не отправляет команды оборудованию и оставляет оператора финальным лицом принятия решения.
            </p>
          </div>
          <span className="font-mono text-[12px] text-[var(--fg-3)]">событий: {heatEnergyDemoEventBatch.events.length}</span>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button onClick={ingestHeatEnergyDemoEvents} disabled={demoIngestState === 'loading'}>
            {demoIngestState === 'loading' ? 'Загрузка демо-событий' : 'Загрузить демо-события'}
          </Button>
          <span className="text-[12px] text-[var(--fg-3)]">
            {demoIngestState === 'idle' ? 'использует настроенный серверный интерфейс' : demoIngestResult}
          </span>
        </div>
      </section>
      <div className="flex flex-wrap gap-2">
        <Button onClick={confirmAirGap}>Локальное подтверждение изоляции (без доказательной силы)</Button>
        <Button variant="ghost" onClick={prepareReport} disabled={localReportBlocked}>
          Сформировать отчёт
        </Button>
        <Button variant="ghost" onClick={exportReport} disabled={localReportBlocked}>
          Выгрузить отчёт
        </Button>
      </div>
      {localReportBlocked ? (
        <p className="text-[12px] text-[var(--fg-3)]">
          Нормативный режим блокирует локальные отчёты настроек. Доказательность должна приходить из серверной проверки цепочек,
          готовность доказательного пакета и API аудиторских проверок.
        </p>
      ) : null}
      {reportText ? (
        <pre className="max-h-52 overflow-auto whitespace-pre-wrap rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3 font-mono text-[12px] text-[var(--fg-2)]">
          {reportText}
        </pre>
      ) : null}
      <ol className="list-decimal space-y-2 rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-4 pl-8 font-mono text-[12px] text-[var(--fg-2)]">
        {auditRows.map((event) => <li key={event}>{event}</li>)}
      </ol>
    </div>
  )
}
