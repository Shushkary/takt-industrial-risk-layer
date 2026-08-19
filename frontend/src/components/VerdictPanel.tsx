// Панель вердикта — реализует петлю обучения (skin in the game).
// Оператор закрывает кейс вердиктом TP/FP/benign с обоснованием; система
// пересчитывает веса инвариантов и показывает эффект обучения.

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { postVerdict } from '../api/client';
import type { Case, VerdictKind, VerdictResult } from '../types/api';

const KIND_META: Record<VerdictKind, { label: string; hint: string; cls: string }> = {
  tp: { label: 'True Positive', hint: 'Реальный инцидент — усилить инварианты', cls: 'v-tp' },
  fp: { label: 'False Positive', hint: 'Ложное срабатывание — ослабить инварианты', cls: 'v-fp' },
  benign: { label: 'Benign', hint: 'Легитимная активность — зафиксировать наблюдение', cls: 'v-benign' },
};

interface VerdictPanelProps {
  caseData: Case;
}

export function VerdictPanel({ caseData }: VerdictPanelProps) {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<VerdictKind | null>(null);
  const [reason, setReason] = useState('');
  const [riskFeedback, setRiskFeedback] = useState<'too_high' | 'too_low' | null>(null);
  const [result, setResult] = useState<VerdictResult | null>(null);

  const mutation = useMutation({
    mutationFn: () => postVerdict(caseData.id, kind!, reason.trim(), riskFeedback),
    onSuccess: (res) => {
      setResult(res);
      queryClient.invalidateQueries({ queryKey: ['case', caseData.id] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      queryClient.invalidateQueries({ queryKey: ['model'] });
    },
  });

  // Уже вынесен вердикт — показываем его и эффект обучения.
  if (caseData.verdict) {
    const meta = KIND_META[caseData.verdict.verdict];
    return (
      <div className="verdict-done">
        <div className={`verdict-tag ${meta.cls}`}>{meta.label}</div>
        <div className="verdict-reason">«{caseData.verdict.reason || 'без комментария'}»</div>
        <div className="verdict-meta">{caseData.verdict.operator} · {new Date(caseData.verdict.ts).toLocaleString('ru-RU')}</div>
        {result && <LearningEffect result={result} />}
      </div>
    );
  }

  return (
    <div className="verdict-form">
      <div className="verdict-kinds">
        {(Object.keys(KIND_META) as VerdictKind[]).map((k) => (
          <button
            key={k}
            type="button"
            className={`verdict-kind ${KIND_META[k].cls}${kind === k ? ' is-sel' : ''}`}
            onClick={() => setKind(k)}
            title={KIND_META[k].hint}
          >
            {KIND_META[k].label}
          </button>
        ))}
      </div>

      {kind && <div className="verdict-hint">{KIND_META[kind].hint}</div>}

      <textarea
        className="verdict-textarea"
        placeholder="Обоснование вердикта (обязательно для разбора и обучения модели)…"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        rows={3}
      />

      <div className="verdict-risk-fb">
        <span className="vrf-label">Оценка риска движка:</span>
        <button type="button" className={`vrf-btn${riskFeedback === 'too_high' ? ' is-sel' : ''}`} onClick={() => setRiskFeedback(riskFeedback === 'too_high' ? null : 'too_high')}>завышен</button>
        <button type="button" className={`vrf-btn${riskFeedback === 'too_low' ? ' is-sel' : ''}`} onClick={() => setRiskFeedback(riskFeedback === 'too_low' ? null : 'too_low')}>занижен</button>
      </div>

      <button
        type="button"
        className="verdict-submit"
        disabled={!kind || reason.trim().length < 3 || mutation.isPending}
        onClick={() => mutation.mutate()}
      >
        {mutation.isPending ? 'Фиксация…' : 'Вынести вердикт и закрыть'}
      </button>
      {mutation.isError && <div className="verdict-error">Ошибка: {(mutation.error as Error).message}</div>}
    </div>
  );
}

function LearningEffect({ result }: { result: VerdictResult }) {
  if (result.adjusted_invariants.length === 0 && result.affected_cases.length === 0) {
    return <div className="learn-note">Наблюдение зафиксировано. Веса инвариантов без изменений.</div>;
  }
  return (
    <div className="learn-effect">
      <div className="learn-title">Модель откалибрована</div>
      {result.adjusted_invariants.map((a) => (
        <div className="learn-row" key={a.invariant}>
          <span className="learn-inv">{a.invariant}</span>
          <span className="learn-delta">{a.before.toFixed(2)} → <strong>{a.after.toFixed(2)}</strong></span>
        </div>
      ))}
      {result.affected_cases.length > 0 && (
        <div className="learn-affected">Пересчитан риск ещё {result.affected_cases.length} кейс(ов) с общими инвариантами</div>
      )}
    </div>
  );
}
