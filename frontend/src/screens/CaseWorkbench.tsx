// Рабочий стол кейса — трёхпанельный layout с вкладками (строгий кибербез-стиль).

import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import * as Tabs from '@radix-ui/react-tabs';
import { ReactFlowProvider } from 'reactflow';
import { format } from 'date-fns';
import { fetchCaseById, fetchAttackChain, fetchEventsByCaseId, updateCaseStatus } from '../api/client';
import { AttackGraph } from '../components/AttackGraph';
import { Timeline } from '../components/Timeline';
import { EventList } from '../components/EventList';
import { EntityCard } from '../components/EntityCard';
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

  const closeCaseMutation = useMutation({
    mutationFn: () => updateCaseStatus(caseId!, 'resolved'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case', caseId] });
      navigate('/');
    },
    onError: (error) => {
      alert(`Ошибка: ${error.message}`);
    },
  });

  if (caseLoading) {
    return <div className="wb-loading">Загрузка кейса…</div>;
  }

  if (!caseData) {
    return <div className="wb-loading" style={{ color: theme.colors.error }}>Кейс не найден</div>;
  }

  const severity = severityMeta[caseData.severity];
  const risk = Math.round(caseData.risk_score * 100);

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
          <div className="case-sub">{caseData.id} · {statusLabels[caseData.status]}</div>
        </div>
        <span className="risk-chip" style={{ '--severity-color': severity.color } as React.CSSProperties}>
          TAKT RISK <span className="risk-chip-num">{risk}</span>/100
        </span>
        {caseData.status !== 'resolved' ? (
          <button
            className="wb-close"
            style={{ width: 'auto', marginTop: 0, padding: '0 18px', minHeight: 40 }}
            type="button"
            disabled={closeCaseMutation.isPending}
            onClick={() => {
              if (confirm('Закрыть кейс?')) closeCaseMutation.mutate();
            }}
          >
            {closeCaseMutation.isPending ? 'Закрытие…' : '✓ Закрыть кейс'}
          </button>
        ) : (
          <span className="status-pill" style={{ '--status-color': theme.colors.resolved } as React.CSSProperties}>
            Закрыт
          </span>
        )}
      </div>

      <div className="wb-layout">
        {/* Левая панель — контекст кейса */}
        <div className="wb-left">
          <div className="wb-panel-title">XAI · почему это инцидент</div>
          <div className="xai-callout" style={{ margin: '0 0 16px' }}>
            {caseData.xai_summary}
          </div>

          <div className="wb-panel-title">Метаданные</div>
          <div className="wb-meta-row"><span>Создан</span><span>{format(new Date(caseData.created_at), 'dd.MM.yyyy HH:mm')}</span></div>
          <div className="wb-meta-row"><span>Обновлён</span><span>{format(new Date(caseData.updated_at), 'dd.MM.yyyy HH:mm')}</span></div>
          <div className="wb-meta-row"><span>Статус</span><span>{statusLabels[caseData.status]}</span></div>

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
