export function TopologyMap() {
  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">Карта сегмента</h1>
      <p className="max-w-[72ch] text-[13px] text-[var(--fg-2)]">
        Заглушка экрана 5: полноэкранный 2D-граф, фильтры, временная шкала — следующий этап (Cytoscape.js / Sigma.js).
      </p>
      <div className="min-h-[480px] rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-4">
        <div className="flex h-full min-h-[440px] items-center justify-center border border-dashed border-[var(--line-strong)] bg-[var(--bg-0)] text-[var(--fg-2)]">
          Topology canvas
        </div>
      </div>
    </div>
  )
}
