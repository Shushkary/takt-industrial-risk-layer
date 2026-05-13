import { useParams } from 'react-router-dom'
import { RiskBadge } from '../components/ui/RiskBadge'
import { Button } from '../components/ui/Button'

export function CaseDetail() {
  const { id } = useParams()

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">Карточка инцидента</h1>
          <p className="mt-1 font-mono text-[16px] text-[var(--fg-1)]">case_id: {id ?? '—'}</p>
        </div>
        <RiskBadge value={0.812} />
      </div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {['Что произошло', 'Почему это необычно', 'Рекомендуемое действие', 'Условия нормальности'].map((title) => (
          <section key={title} className="rounded-takt border border-[var(--line)] bg-[var(--bg-1)] p-3">
            <h2 className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">{title}</h2>
            <p className="mt-2 text-[13px] text-[var(--fg-2)]">XAI-блок (мок). Подключение к ответу API — следующий этап.</p>
          </section>
        ))}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="ghost">TRIAGE</Button>
        <Button variant="ghost">CONFIRMED</Button>
        <Button variant="ghost">FALSE_POSITIVE</Button>
        <Button variant="ghost">EXPECTED_BEHAVIOR</Button>
        <Button variant="ghost">CLOSED</Button>
      </div>
      <p className="text-[12px] text-[var(--fg-3)]">
        HITL: смена статуса только явным действием; для EXPECTED_BEHAVIOR потребуется обоснование (валидация формы) —
        следующий этап.
      </p>
    </div>
  )
}
