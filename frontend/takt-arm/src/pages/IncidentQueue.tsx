export function IncidentQueue() {
  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">Очередь инцидентов</h1>
      <p className="max-w-[72ch] text-[13px] text-[var(--fg-2)]">
        Заглушка экрана 2: виртуализированная таблица до 50 000 строк, фильтры-чипы, детальная панель — следующий этап
        (TanStack Virtual / аналог).
      </p>
      <div className="overflow-hidden rounded-takt border border-[var(--line)]">
        <table className="w-full border-collapse text-left text-[13px]">
          <thead className="border-b border-[var(--line)] bg-[var(--bg-2)] text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
            <tr>
              <th className="px-3 py-2">Время</th>
              <th className="px-3 py-2">Узел</th>
              <th className="px-3 py-2">Инвариант</th>
              <th className="px-3 py-2 font-mono tabular-nums">Risk Index</th>
              <th className="px-3 py-2">Статус</th>
            </tr>
          </thead>
          <tbody className="text-[var(--fg-1)]">
            <tr className="border-b border-[var(--line)] bg-[var(--bg-1)]">
              <td className="px-3 py-2 font-mono tabular-nums text-[var(--fg-2)]">13.05.2026 02:14:08</td>
              <td className="px-3 py-2">plc-assembly-03</td>
              <td className="px-3 py-2">jump_server_bypass</td>
              <td className="px-3 py-2 font-mono tabular-nums">0,812</td>
              <td className="px-3 py-2">TRIAGE</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  )
}
