export function SettingsAudit() {
  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">Настройки и аудит</h1>
      <p className="max-w-[72ch] text-[13px] text-[var(--fg-2)]">
        Заглушка экрана 6: SBOM, версии модулей, журнал действий оператора, индикатор изоляции контура — следующий этап.
      </p>
      <div className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-4">
        <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Air-gap</div>
        <p className="mt-2 text-[13px] text-[var(--fg-2)]">
          Индикатор отсутствия исходящих соединений из браузера — будет завязан на политику поставки и nginx/CSP.
        </p>
      </div>
    </div>
  )
}
