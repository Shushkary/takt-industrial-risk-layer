import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { BookOpen, FileText, LayoutDashboard, ListTodo, Map, Settings } from 'lucide-react'
import { useUiStore, type SegmentMode, type ShiftPhase } from '../store/uiStore'
import { Chip } from '../components/ui/Chip'
import { fetchComplianceMode, fetchReady, taktApiConfigured, type ComplianceModeResponse, type ReadyResponse } from '../app/taktApi'
import { demoIncidents, demoScenarios, useDemoStore, type DemoScenarioId } from '../demo'

const firstDemoIncidentId = demoIncidents[0]?.id ?? 'demo'

const nav = [
  { to: '/', label: 'Обзор сегмента', icon: LayoutDashboard },
  { to: '/incidents', label: 'Очередь инцидентов', icon: ListTodo },
  { to: `/cases/${firstDemoIncidentId}`, label: 'Карточка инцидента', icon: FileText },
  { to: '/invariants', label: 'Библиотека инвариантов', icon: BookOpen },
  { to: '/topology', label: 'Карта сегмента', icon: Map },
  { to: '/settings', label: 'Настройки и аудит', icon: Settings },
] as const

const segmentModeLabels: Record<SegmentMode, string> = {
  NORMAL: 'Штатный',
  DEGRADED: 'Деградация',
  'AIR-GAP': 'Изоляция',
  STORM: 'Пик нагрузки',
}

const shiftPhaseLabels: Record<ShiftPhase, string> = {
  WORK: 'Рабочая',
  NIGHT: 'Ночь',
  MAINT: 'Обслуживание',
}

function complianceEnabled(mode: ComplianceModeResponse | null): boolean {
  return mode?.compliance_enabled === true
}

function readyOk(value: ReadyResponse | null): boolean {
  return value?.status === 'ready' || value?.ok === true || value?.ready === true
}

export function AppShell() {
  const { segmentMode, shiftPhase, setSegmentMode, setShiftPhase } = useUiStore()
  const { scenarioId, setScenarioId } = useDemoStore()
  const apiConfigured = taktApiConfigured()
  const [complianceMode, setComplianceMode] = useState<ComplianceModeResponse | null>(null)
  const [complianceState, setComplianceState] = useState<'local' | 'loading' | 'loaded' | 'error'>(
    apiConfigured ? 'loading' : 'local',
  )
  const [readyState, setReadyState] = useState<'local' | 'loading' | 'ready' | 'not-ready' | 'error'>(
    apiConfigured ? 'loading' : 'local',
  )
  const complianceOn = complianceEnabled(complianceMode)
  const demoControlsDisabled = apiConfigured || complianceOn

  useEffect(() => {
    let cancelled = false
    if (!apiConfigured) {
      setComplianceMode(null)
      setComplianceState('local')
      return
    }
    setComplianceState('loading')
    fetchComplianceMode()
      .then((mode) => {
        if (cancelled) {
          return
        }
        setComplianceMode(mode)
        setComplianceState('loaded')
      })
      .catch(() => {
        if (!cancelled) {
          setComplianceMode(null)
          setComplianceState('error')
        }
      })
    return () => {
      cancelled = true
    }
  }, [apiConfigured])

  useEffect(() => {
    let cancelled = false
    if (!apiConfigured) {
      setReadyState('local')
      return
    }
    setReadyState('loading')
    fetchReady()
      .then((ready) => {
        if (!cancelled) {
          setReadyState(readyOk(ready) ? 'ready' : 'not-ready')
        }
      })
      .catch(() => {
        if (!cancelled) {
          setReadyState('error')
        }
      })
    return () => {
      cancelled = true
    }
  }, [apiConfigured])

  return (
    <div className="flex min-h-screen bg-[var(--bg-0)] text-[var(--fg-1)]">
      <aside className="flex w-56 shrink-0 flex-col border-r border-[var(--line)] bg-[var(--bg-1)]">
        <div className="border-b border-[var(--line)] px-3 py-3">
          <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">ТАКТ</div>
          <div className="text-[13px] text-[var(--fg-2)]">Промышленный слой риска</div>
        </div>
        <nav className="flex flex-1 flex-col gap-1 p-2" aria-label="Основная навигация">
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-2 rounded-takt px-2 py-2 text-[13px] takt-focus-ring transition-colors duration-150 ease-[cubic-bezier(0.2,0,0,1)] ${
                  isActive
                    ? 'border border-[var(--line-strong)] bg-[var(--bg-2)] text-[var(--fg-1)]'
                    : 'border border-transparent text-[var(--fg-2)] hover:bg-[var(--bg-2)] hover:text-[var(--fg-1)]'
                }`
              }
            >
              <Icon className="h-4 w-4 shrink-0" strokeWidth={1.5} aria-hidden />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-[var(--line)] p-2 text-[11px] text-[var(--fg-3)]">
          Минимальный продукт · без внешних сетевых вызовов
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] bg-[var(--bg-1)] px-4 py-2">
          <span
            className={`rounded-takt border px-2 py-0.5 font-mono text-[12px] ${
              complianceOn
                ? 'border-[var(--teal-1)] bg-[var(--teal-3)] text-[var(--fg-1)]'
                : 'border-[var(--line)] bg-[var(--bg-2)] text-[var(--fg-2)]'
            }`}
            title="Режим compliance читается из /compliance/mode при настроенном backend API."
          >
            {complianceOn
              ? 'Compliance включён'
              : complianceState === 'loading'
                ? 'Compliance загружается'
                : complianceState === 'error'
                  ? 'Compliance недоступен'
                  : 'Compliance выключен'}
          </span>
          {apiConfigured ? (
            <span
              className={`rounded-takt border px-2 py-0.5 font-mono text-[12px] ${
                readyState === 'ready'
                  ? 'border-[var(--teal-1)] bg-[var(--teal-3)] text-[var(--fg-1)]'
                  : 'border-[var(--amber-1)] bg-[rgba(245,158,11,0.08)] text-[var(--amber-1)]'
              }`}
              title="Готовность backend читается из /ready."
            >
              {readyState === 'ready'
                ? 'API готов'
                : readyState === 'loading'
                  ? 'API готовность загружается'
                  : readyState === 'not-ready'
                    ? 'API не готов'
                    : 'API готовность недоступна'}
            </span>
          ) : null}
          {!apiConfigured ? (
            <span className="rounded-takt border border-[var(--amber-1)] bg-[rgba(245,158,11,0.08)] px-2 py-0.5 text-[12px] text-[var(--amber-1)]">
              Локальный демонстрационный режим
            </span>
          ) : null}
          <span className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Режим сегмента</span>
          {(['NORMAL', 'DEGRADED', 'AIR-GAP', 'STORM'] as const).map((mode) => (
            <Chip
              key={mode}
              active={segmentMode === mode}
              aria-pressed={segmentMode === mode}
              disabled={demoControlsDisabled}
              onClick={() => setSegmentMode(mode)}
            >
              {segmentModeLabels[mode]}
            </Chip>
          ))}
          <span className="ml-4 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Фаза</span>
          {(['WORK', 'NIGHT', 'MAINT'] as const).map((phase) => (
            <Chip
              key={phase}
              active={shiftPhase === phase}
              aria-pressed={shiftPhase === phase}
              disabled={demoControlsDisabled}
              onClick={() => setShiftPhase(phase)}
            >
              {shiftPhaseLabels[phase]}
            </Chip>
          ))}
          <label className="ml-4 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]" htmlFor="demo-scenario">
            Сценарий
          </label>
          <select
            id="demo-scenario"
            value={scenarioId}
            disabled={demoControlsDisabled}
            onChange={(event) => setScenarioId(event.target.value as DemoScenarioId)}
            className="rounded-takt border border-[var(--line)] bg-[var(--bg-2)] px-2 py-1 text-[12px] text-[var(--fg-1)] takt-focus-ring"
          >
            {demoScenarios.map((scenario) => (
              <option key={scenario.id} value={scenario.id}>
                {scenario.title}
              </option>
            ))}
          </select>
          {demoControlsDisabled ? (
            <span className="text-[12px] text-[var(--amber-1)]">
              {apiConfigured ? 'Демо-режим отключён в API-режиме.' : 'Демо-режим отключён в compliance-режиме.'}
            </span>
          ) : null}
          <span className="ml-auto font-mono text-[12px] text-[var(--fg-2)] tabular-nums" aria-live="polite">
            {new Intl.DateTimeFormat('ru-RU', {
              dateStyle: 'short',
              timeStyle: 'medium',
              timeZone: 'Europe/Moscow',
            }).format(new Date())}{' '}
            МСК
          </span>
        </header>
        <main className="min-h-0 flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}


