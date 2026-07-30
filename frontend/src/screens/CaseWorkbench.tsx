// Рабочий стол кейса — трёхпанельный layout с вкладками

import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import * as Tabs from '@radix-ui/react-tabs';
import { ReactFlowProvider } from 'reactflow';
import { fetchCaseById, fetchAttackChain, fetchEventsByCaseId, updateCaseStatus } from '../api/client';
import { AttackGraph } from '../components/AttackGraph';
import { Timeline } from '../components/Timeline';
import { EventList } from '../components/EventList';
import { EntityCard } from '../components/EntityCard';
import { theme } from '../styles/theme';
import { format } from 'date-fns';
import type { Case } from '../types/api';

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
      alert('Кейс закрыт');
      navigate('/');
    },
    onError: (error) => {
      alert(`Ошибка: ${error.message}`);
    },
  });
  
  if (caseLoading) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
          backgroundColor: theme.colors.background,
          color: theme.colors.textMuted,
        }}
      >
        Загрузка кейса...
      </div>
    );
  }
  
  if (!caseData) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
          backgroundColor: theme.colors.background,
          color: theme.colors.error,
        }}
      >
        Кейс не найден
      </div>
    );
  }
  
  const getSeverityColor = (severity: Case['severity']) => {
    switch (severity) {
      case 'critical':
        return theme.colors.critical;
      case 'high':
        return theme.colors.high;
      case 'medium':
        return theme.colors.medium;
      case 'low':
        return theme.colors.low;
    }
  };
  
  const getStatusLabel = (status: Case['status']) => {
    switch (status) {
      case 'new':
        return 'Новый';
      case 'investigating':
        return 'В работе';
      case 'resolved':
        return 'Закрыт';
    }
  };
  
  return (
    <div
      style={{
        display: 'flex',
        height: '100vh',
        backgroundColor: theme.colors.background,
      }}
    >
      {/* Левая панель — контекст кейса (20%) */}
      <div
        style={{
          width: '20%',
          padding: theme.spacing.lg,
          backgroundColor: theme.colors.surface,
          borderRight: `1px solid ${theme.colors.border}`,
          overflowY: 'auto',
        }}
      >
        {/* Кнопка назад */}
        <button
          onClick={() => navigate('/')}
          style={{
            marginBottom: theme.spacing.lg,
            padding: `${theme.spacing.sm} ${theme.spacing.md}`,
            backgroundColor: 'transparent',
            color: theme.colors.accent,
            border: `1px solid ${theme.colors.accent}`,
            borderRadius: theme.borderRadius.sm,
            cursor: 'pointer',
            width: '100%',
          }}
        >
          ← Назад к очереди
        </button>
        
        {/* Severity badge */}
        <div
          style={{
            display: 'inline-block',
            padding: `${theme.spacing.xs} ${theme.spacing.md}`,
            borderRadius: theme.borderRadius.sm,
            backgroundColor: getSeverityColor(caseData.severity) + '33',
            color: getSeverityColor(caseData.severity),
            fontWeight: 600,
            fontSize: theme.typography.fontSize.sm,
            textTransform: 'uppercase',
            marginBottom: theme.spacing.md,
          }}
        >
          {caseData.severity}
        </div>
        
        {/* ID кейса */}
        <h2 style={{ marginBottom: theme.spacing.sm, fontSize: theme.typography.fontSize.lg }}>
          Кейс #{caseData.id.slice(0, 8)}
        </h2>
        
        {/* Статус */}
        <div
          style={{
            fontSize: theme.typography.fontSize.sm,
            color: theme.colors.textSecondary,
            marginBottom: theme.spacing.md,
          }}
        >
          Статус: <span style={{ fontWeight: 600 }}>{getStatusLabel(caseData.status)}</span>
        </div>
        
        {/* Время */}
        <div
          style={{
            fontSize: theme.typography.fontSize.xs,
            color: theme.colors.textMuted,
            marginBottom: theme.spacing.lg,
          }}
        >
          <div>Создан: {format(new Date(caseData.created_at), 'dd.MM.yyyy HH:mm')}</div>
          <div>Обновлён: {format(new Date(caseData.updated_at), 'dd.MM.yyyy HH:mm')}</div>
        </div>
        
        {/* Находки */}
        <div style={{ marginBottom: theme.spacing.lg }}>
          <h3
            style={{
              fontSize: theme.typography.fontSize.md,
              marginBottom: theme.spacing.sm,
              color: theme.colors.textSecondary,
            }}
          >
            Находки ({caseData.findings.length})
          </h3>
          {caseData.findings.length === 0 ? (
            <div style={{ fontSize: theme.typography.fontSize.sm, color: theme.colors.textMuted }}>
              Пока нет находок
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing.sm }}>
              {caseData.findings.map((finding) => (
                <div
                  key={finding.id}
                  style={{
                    padding: theme.spacing.sm,
                    backgroundColor: theme.colors.background,
                    borderRadius: theme.borderRadius.sm,
                    fontSize: theme.typography.fontSize.xs,
                  }}
                >
                  <div style={{ fontWeight: 600 }}>{finding.entity_type}</div>
                  <div style={{ color: theme.colors.textMuted, wordBreak: 'break-all' }}>
                    {finding.entity_id}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        
        {/* Кнопка закрытия кейса */}
        {caseData.status !== 'resolved' && (
          <button
            onClick={() => {
              if (confirm('Закрыть кейс?')) {
                closeCaseMutation.mutate();
              }
            }}
            disabled={closeCaseMutation.isPending}
            style={{
              padding: `${theme.spacing.sm} ${theme.spacing.md}`,
              backgroundColor: theme.colors.success,
              color: theme.colors.background,
              border: 'none',
              borderRadius: theme.borderRadius.sm,
              cursor: closeCaseMutation.isPending ? 'not-allowed' : 'pointer',
              fontWeight: 600,
              width: '100%',
              opacity: closeCaseMutation.isPending ? 0.6 : 1,
            }}
          >
            {closeCaseMutation.isPending ? 'Закрытие...' : 'Закрыть кейс'}
          </button>
        )}
      </div>
      
      {/* Центральная панель — вкладки (60%) */}
      <div style={{ width: '60%', display: 'flex', flexDirection: 'column' }}>
        <Tabs.Root defaultValue="graph" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
          <Tabs.List
            style={{
              display: 'flex',
              borderBottom: `1px solid ${theme.colors.border}`,
              backgroundColor: theme.colors.surface,
            }}
          >
            <TabTrigger value="graph">Граф</TabTrigger>
            <TabTrigger value="timeline">Таймлайн</TabTrigger>
            <TabTrigger value="events">События</TabTrigger>
          </Tabs.List>
          
          <Tabs.Content value="graph" style={{ flex: 1, overflow: 'hidden' }}>
            {chainLoading ? (
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  height: '100%',
                  color: theme.colors.textMuted,
                }}
              >
                Загрузка графа...
              </div>
            ) : attackChain ? (
              <ReactFlowProvider>
                <AttackGraph attackChain={attackChain} />
              </ReactFlowProvider>
            ) : (
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  height: '100%',
                  color: theme.colors.textMuted,
                }}
              >
                Нет данных графа
              </div>
            )}
          </Tabs.Content>
          
          <Tabs.Content value="timeline" style={{ flex: 1, overflow: 'hidden', padding: theme.spacing.md }}>
            {eventsLoading ? (
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  height: '100%',
                  color: theme.colors.textMuted,
                }}
              >
                Загрузка таймлайна...
              </div>
            ) : (
              <Timeline events={events} width={window.innerWidth * 0.6 - 32} height={window.innerHeight - 100} />
            )}
          </Tabs.Content>
          
          <Tabs.Content value="events" style={{ flex: 1, overflow: 'hidden' }}>
            {eventsLoading ? (
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  height: '100%',
                  color: theme.colors.textMuted,
                }}
              >
                Загрузка событий...
              </div>
            ) : (
              <EventList events={events} />
            )}
          </Tabs.Content>
        </Tabs.Root>
      </div>
      
      {/* Правая панель — EntityCard (20%) */}
      <div
        style={{
          width: '20%',
          padding: theme.spacing.lg,
          backgroundColor: theme.colors.surface,
          borderLeft: `1px solid ${theme.colors.border}`,
          overflowY: 'auto',
        }}
      >
        <EntityCard caseId={caseId} />
      </div>
    </div>
  );
}

// Вкладка Radix UI
function TabTrigger({ value, children }: { value: string; children: React.ReactNode }) {
  return (
    <Tabs.Trigger
      value={value}
      style={{
        padding: `${theme.spacing.md} ${theme.spacing.lg}`,
        backgroundColor: 'transparent',
        border: 'none',
        color: theme.colors.textSecondary,
        cursor: 'pointer',
        fontWeight: 600,
        fontSize: theme.typography.fontSize.sm,
        borderBottom: '2px solid transparent',
        transition: theme.transitions.fast,
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.color = theme.colors.textPrimary;
      }}
      onMouseLeave={(e) => {
        if (!e.currentTarget.hasAttribute('data-state') || e.currentTarget.getAttribute('data-state') !== 'active') {
          e.currentTarget.style.color = theme.colors.textSecondary;
        }
      }}
      data-active-style={{
        color: theme.colors.accent,
        borderBottomColor: theme.colors.accent,
      }}
    >
      {children}
    </Tabs.Trigger>
  );
}
