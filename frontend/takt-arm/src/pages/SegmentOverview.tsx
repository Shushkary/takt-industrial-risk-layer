import { MetricTile } from '../components/ui/MetricTile'
import { RiskBadge } from '../components/ui/RiskBadge'
import { useUiStore } from '../store/uiStore'

export function SegmentOverview() {
  const { segmentMode, partialObservability } = useUiStore()

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-[20px] font-semibold tracking-tight text-[var(--fg-1)]">Обзор сегмента</h1>
        <p className="mt-1 max-w-[72ch] text-[13px] text-[var(--fg-2)]">
          Заглушка экрана 1: causal mesh, ритм, топ-5 инцидентов и DQ — будут подключены к API ТАКТ. Сейчас — каркас и
          токены по чек-листу.
        </p>
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        <MetricTile label="Режим" value={segmentMode} hint="NORMAL / DEGRADED / AIR-GAP / STORM" />
        <MetricTile
          label="partial_observability"
          value={`${(partialObservability * 100).toFixed(0)} %`}
          hint="В DEGRADED должен быть явно виден пересчёт риска"
        />
        <RiskBadge value={0.873} />
      </div>
      <section
        className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-4"
        aria-label="Зона causal mesh (заглушка)"
      >
        <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Causal Mesh</div>
        <div className="mt-3 flex h-64 items-center justify-center border border-dashed border-[var(--line-strong)] bg-[var(--bg-0)] text-[var(--fg-2)]">
          Граф (Cytoscape.js / Sigma.js) — следующий этап
        </div>
      </section>
    </div>
  )
}
