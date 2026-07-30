// Рабочий стол кейса — трёхпанельный layout с вкладками (строгий кибербез-стиль).
// Антихрупкость: риск±доверие + импакт + «тихий хвост», via negativa (фальсификаторы),
// queue lock, эскалация, вердикт с петлёй обучения.

import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import * as Tabs from '@radix-ui/react-tabs';
import { ReactFlowProvider } from 'reactflow';
import { format } from 'date-fns';
import {
  fetchCaseById, fetchAttackChain, fetchEventsByCaseId,
  lockCase, unlockCase, escalateCase,
} from '../api/client';
import { AttackGraph } from '../components/AttackGraph';
import { Timeline } from '../components/Timeline';
import { EventList } from '../components/EventList';
import { EntityCard } from '../components/EntityCard';
import { VerdictPanel } from '../components/VerdictPanel';
import { theme } from '../styles/theme';
import type { Case } from '../types/api';

const severityMeta: Record<Case['severity'], { code: string; color: string }> = {
  critical: { code: 'CRIT', color: theme.colors.critical },
  high: { code: 'HIGH', color: theme.colors.high },
  medium: { code: 'MED', color: theme.colors.medium },
  low: { code: 'LOW', color: theme.colors.low },
};

const statusLabels: Record<Case['status'], string> = {
  new: 'Новый',
  investigating: 'В работе',
  resolved: 'Закрыт',
};

export function CaseWorkbench() {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: caseData, isLoading: caseLoading } = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => fetchCaseById(caseId!),
    enabled: !!caseId,
  });

  const { data: attackChain, isLoading: chainLoading } = useQuery({
    queryKey: ['attackChain', caseId],
    queryFn: () => fetchAttackChain(caseId!),
    enabled: !!caseId,
  });

  const { data: events = [], isLoading: eventsLoading } = useQuery({
    queryKey: ['events', caseId],
    queryFn: () => fetchEventsByCaseId(caseId!),
    enabled: !!caseId,
  });

  const invalidateCase = () => {
    queryClient.invalidateQueries({ queryKey: ['case', caseId] });
    queryClient.invalidateQueries({ queryKey: ['cases'] });
  };

  const lockMut = useMutation({
    mutationFn: () => lockCase(caseId!),
    onSuccess: (res) => {
      if (res.conflict) alert(`Кейс уже в работе у ${res.operator}`);
      invalidateCase();
    },
  });
  const unlockMut = useMutation({
    mutationFn: () => unlockCase(caseId!),
    onSuccess: invalidateCase,
  });
  const escalateMut = useMutation({
    mutationFn: () => escalateCase(caseId!),
    onSuccess: invalidateCase,
  });

  if (caseLoading) {
    return <div className="wb-loading">Загрузка кейса…</div>;
  }

  if (!caseData) {
    return <div className="wb-loading" style={{ color: theme.colors.error }}>Кейс не найден</div>;
  }

  const severity = severityMeta[caseData.severity];
  const risk = Math.round(caseData.risk_score * 100);
  const impact = Math.round((caseData.impact_score ?? 0) * 100);
  const conf = caseData.confidence ?? 0;
  const isTail = caseData.tail_risk;
  const locked = Boolean(caseData.lock);

  return (
    <div>
      {/* Верхняя панель кейса */}
      <div className="case-topbar" style={{ '--severity-color': severity.color } as React.CSSProperties}>
        <button className="back-button" type="button" onClick={() => navigate('/')}>
          <span aria-hidden="true">←</span> Очередь
        </button>
        <span className="severity-pill" style={{ '--severity-color': severity.color } as React.CSSProperties}>
          {severity.code}
        </span>
        <div className="case-heading">
          <h1>{caseData.title}</h1>
          <div className="case-sub">
            {caseData.id} · {statusLabels[caseData.status]}
            {caseData.escalated && <span className="esc-tag">L2</span>}
            {locked && <span className="lock-tag">🔒 {caseData.lock?.operator}</span>}
          </div>
        </div>

        {/* Барбелл-метрики: риск / импакт / доверие */}
        <div className="metric-cluster">
          <span className="risk-chip" style={{ '--severity-color': severity.color } as React.CSSProperties}>
            RISK <span className="risk-chip-num">{risk}</span>
          </span>
          <span className="impact-chip" title="Физический импакт на АСУ ТП">
            ИМПАКТ <span className="impact-chip-num">{impact}</span>
          </span>
          <span className={`conf-chip${conf < 0.5 ? ' is-low' : ''}`} title={`наблюдений: ${caseData.observations ?? '—'}`}>
            ДОВЕРИЕ <span className="conf-chip-num">{conf.toFixed(2)}</span>
          </span>
          {isTail && <span className="tail-chip topbar-tail" title="Низкая вероятность, катастрофический импакт">ХВОСТ OT</span>}
        </div>

        <div className="wb-actions">
          {!locked ? (
            <button className="wb-act-btn" type="button" onClick={() => lockMut.mutate()} disabled={lockMut.isPending}>Взять в работу</button>
          ) : (
            <button className="wb-act-btn ghost" type="button" onClick={() => unlockMut.mutate()} disabled={unlockMut.isPending}>Снять лок</button>
          )}
          {!caseData.escalated && caseData.status !== 'resolved' && (
            <button className="wb-act-btn ghost" type="button" onClick={() => escalateMut.mutate()} disabled={escalateMut.isPending}>Эскалация L2</button>
          )}
        </div>
      </div>

      <div className="wb-layout">
        {/* Левая панель — контекст кейса */}
        <div className="wb-left">
          <div className="wb-panel-title">XAI · почему это инцидент</div>
          <div className="xai-callout" style={{ margin: '0 0 16px' }}>
            {caseData.xai_summary}
          </div>

          {/* via negativa: чем можно ОТМЕНИТЬ вердикт */}
          {caseData.falsifiers && caseData.falsifiers.length > 0 && (
            <>
              <div className="wb-panel-title">Что отменило бы вердикт (via negativa)</div>
              <ul className="falsifier-list">
                {caseData.falsifiers.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            </>
          )}

          <div className="wb-panel-title" style={{ marginTop: 18 }}>Метаданные</div>
          <div className="wb-meta-row"><span>Создан</span><span>{format(new Date(caseData.created_at), 'dd.MM.yyyy HH:mm')}</span></div>
          <div className="wb-meta-row"><span>Обновлён</span><span>{format(new Date(caseData.updated_at), 'dd.MM.yyyy HH:mm')}</span></div>
          <div className="wb-meta-row"><span>Наблюдений</span><span>{caseData.observations ?? '—'}</span></div>
          {caseData.invariants && caseData.invariants.length > 0 && (
            <div className="wb-meta-row"><span>Инварианты</span><span className="mono-small">{caseData.invariants.join(', ')}</span></div>
          )}

          <div className="wb-panel-title" style={{ marginTop: 18 }}>
            Находки · {caseData.findings.length}
          </div>
          {caseData.findings.length === 0 ? (
            <div style={{ color: theme.colors.textMuted, fontSize: 12 }}>Пока нет находок</div>
          ) : (
            caseData.findings.map((finding) => (
              <div className="wb-finding" key={finding.id}>
                <div className="f-type">{finding.entity_type}</div>
                <div className="f-id">{finding.entity_id}</div>
              </div>
            ))
          )}

          {/* Вердикт с петлёй обучения */}
          <div className="wb-panel-title" style={{ marginTop: 18 }}>Вердикт · петля обучения</div>
          <VerdictPanel caseData={caseData} />
        </div>

        {/* Центральная панель — вкладки */}
        <div className="wb-center">
          <Tabs.Root defaultValue="graph" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            <Tabs.List className="wb-tabs">
              <Tabs.Trigger className="wb-tab" value="graph">Граф атаки</Tabs.Trigger>
              <Tabs.Trigger className="wb-tab" value="timeline">Таймлайн</Tabs.Trigger>
              <Tabs.Trigger className="wb-tab" value="events">События</Tabs.Trigger>
            </Tabs.List>

            <Tabs.Content className="wb-tab-content" value="graph">
              {chainLoading ? (
                <div className="wb-loading">Загрузка графа…</div>
              ) : attackChain ? (
                <ReactFlowProvider>
                  <AttackGraph attackChain={attackChain} />
                </ReactFlowProvider>
              ) : (
                <div className="wb-loading">Нет данных графа</div>
              )}
            </Tabs.Content>

            <Tabs.Content className="wb-tab-content" value="timeline" style={{ padding: theme.spacing.md }}>
              {eventsLoading ? (
                <div className="wb-loading">Загрузка таймлайна…</div>
              ) : (
                <Timeline events={events} width={window.innerWidth - 620 - 32} height={window.innerHeight - 160} />
              )}
            </Tabs.Content>

            <Tabs.Content className="wb-tab-content" value="events">
              {eventsLoading ? (
                <div className="wb-loading">Загрузка событий…</div>
              ) : (
                <EventList events={events} />
              )}
            </Tabs.Content>
          </Tabs.Root>
        </div>

        {/* Правая панель — карточка сущности */}
        <div className="wb-right">
          <div className="wb-panel-title">Карточка сущности</div>
          <EntityCard caseId={caseId} />
        </div>
      </div>
    </div>
  );
}
