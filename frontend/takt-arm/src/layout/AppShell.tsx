import { NavLink, Outlet } from 'react-router-dom'
import { BookOpen, LayoutDashboard, ListTodo, Map, Settings, FileText } from 'lucide-react'
import { useUiStore } from '../store/uiStore'
import { Chip } from '../components/ui/Chip'

const nav = [
  { to: '/', label: 'Обзор сегмента', icon: LayoutDashboard },
  { to: '/incidents', label: 'Очередь инцидентов', icon: ListTodo },
  { to: '/cases/demo', label: 'Карточка инцидента', icon: FileText },
  { to: '/invariants', label: 'Библиотека инвариантов', icon: BookOpen },
  { to: '/topology', label: 'Карта сегмента', icon: Map },
  { to: '/settings', label: 'Настройки и аудит', icon: Settings },
] as const

export function AppShell() {
  const { segmentMode, shiftPhase, setSegmentMode, setShiftPhase } = useUiStore()

  return (
    <div className="flex min-h-screen bg-[var(--bg-0)] text-[var(--fg-1)]">
      <aside className="flex w-56 shrink-0 flex-col border-r border-[var(--line)] bg-[var(--bg-1)]">
        <div className="border-b border-[var(--line)] px-3 py-3">
          <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">ТАКТ</div>
          <div className="text-[13px] text-[var(--fg-2)]">Industrial Risk Layer</div>
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
          MVP UI · без внешних CDN
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] bg-[var(--bg-1)] px-4 py-2">
          <span className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Режим сегмента</span>
          {(['NORMAL', 'DEGRADED', 'AIR-GAP', 'STORM'] as const).map((m) => (
            <Chip key={m} active={segmentMode === m} onClick={() => setSegmentMode(m)}>
              {m}
            </Chip>
          ))}
          <span className="ml-4 text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Фаза</span>
          {(['WORK', 'NIGHT', 'MAINT'] as const).map((p) => (
            <Chip key={p} active={shiftPhase === p} onClick={() => setShiftPhase(p)}>
              {p}
            </Chip>
          ))}
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
