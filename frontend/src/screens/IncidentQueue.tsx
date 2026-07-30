// Очередь инцидентов с SSE, фильтрами и keyboard shortcuts

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { fetchCases, subscribeToUpdates } from '../api/client';
import { useCaseStore } from '../stores/caseStore';
import { KeyboardShortcuts } from '../components/KeyboardShortcuts';
import { theme } from '../styles/theme';
import type { Case } from '../types/api';
import { format } from 'date-fns';

export function IncidentQueue() {
  const navigate = useNavigate();
  const {
    filters,
    toggleSeverityFilter,
    toggleStatusFilter,
    clearFilters,
    focusedIndex,
  } = useCaseStore();
  
  const [liveCases, setLiveCases] = useState<Case[]>([]);
  
  // Начальная загрузка кейсов
  const { data: initialCases, isLoading } = useQuery({
    queryKey: ['cases'],
    queryFn: fetchCases,
  });
  
  // SSE подписка на обновления
  useEffect(() => {
    const unsubscribe = subscribeToUpdates((updatedCase) => {
      setLiveCases((prev) => {
        const index = prev.findIndex((c) => c.id === updatedCase.id);
        if (index >= 0) {
          // Обновление существующего
          const newCases = [...prev];
          newCases[index] = updatedCase;
          return newCases;
        } else {
          // Новый кейс
          return [updatedCase, ...prev];
        }
      });
    });
    
    return unsubscribe;
  }, []);
  
  // Объединение начальных и live кейсов
  const allCases = liveCases.length > 0 ? liveCases : initialCases || [];
  
  // Фильтрация
  const filteredCases = allCases.filter((c) => {
    if (filters.severity && !filters.severity.includes(c.severity)) return false;
    if (filters.status && !filters.status.includes(c.status)) return false;
    return true;
  });
  
  // Сортировка по риску (severity desc → timestamp desc)
  const sortedCases = [...filteredCases].sort((a, b) => {
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    const severityDiff = severityOrder[b.severity] - severityOrder[a.severity];
    if (severityDiff !== 0) return severityDiff;
    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  });
  
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
  
  const getStatusColor = (status: Case['status']) => {
    switch (status) {
      case 'new':
        return theme.colors.new;
      case 'investigating':
        return theme.colors.investigating;
      case 'resolved':
        return theme.colors.resolved;
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
        padding: theme.spacing.xl,
        minHeight: '100vh',
        backgroundColor: theme.colors.background,
      }}
    >
      {/* Заголовок и фильтры */}
      <div style={{ marginBottom: theme.spacing.xl }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: theme.spacing.lg }}>
          <h1 style={{ fontSize: theme.typography.fontSize.xl }}>
            Очередь инцидентов
          </h1>
          <a
            href="/compare"
            onClick={(e) => { e.preventDefault(); navigate('/compare'); }}
            style={{
              color: theme.colors.accent,
              textDecoration: 'none',
              border: `1px solid ${theme.colors.border}`,
              padding: '8px 14px',
              borderRadius: theme.borderRadius.md,
              fontSize: theme.typography.fontSize.sm,
            }}
          >
            ⏱ Сравнение: ручной режим vs ТАКТ
          </a>
        </div>
        
        {/* Фильтры-чипы */}
        <div style={{ display: 'flex', gap: theme.spacing.md, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: theme.spacing.sm, alignItems: 'center' }}>
            <span style={{ color: theme.colors.textSecondary, fontSize: theme.typography.fontSize.sm }}>
              Severity:
            </span>
            {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
              <FilterChip
                key={sev}
                label={sev}
                active={filters.severity?.includes(sev) || false}
                color={getSeverityColor(sev)}
                onClick={() => toggleSeverityFilter(sev)}
              />
            ))}
          </div>
          
          <div style={{ display: 'flex', gap: theme.spacing.sm, alignItems: 'center' }}>
            <span style={{ color: theme.colors.textSecondary, fontSize: theme.typography.fontSize.sm }}>
              Статус:
            </span>
            {(['new', 'investigating', 'resolved'] as const).map((status) => (
              <FilterChip
                key={status}
                label={getStatusLabel(status)}
                active={filters.status?.includes(status) || false}
                color={getStatusColor(status)}
                onClick={() => toggleStatusFilter(status)}
              />
            ))}
          </div>
          
          {(filters.severity || filters.status) && (
            <button
              onClick={clearFilters}
              style={{
                padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
                backgroundColor: 'transparent',
                color: theme.colors.textSecondary,
                border: `1px solid ${theme.colors.border}`,
                borderRadius: theme.borderRadius.sm,
                cursor: 'pointer',
                fontSize: theme.typography.fontSize.sm,
              }}
            >
              Сбросить
            </button>
          )}
        </div>
      </div>
      
      {/* Карточки кейсов */}
      {isLoading && (
        <div style={{ color: theme.colors.textMuted }}>Загрузка...</div>
      )}
      
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
          gap: theme.spacing.lg,
        }}
      >
        <AnimatePresence>
          {sortedCases.map((caseItem, index) => (
            <motion.div
              key={caseItem.id}
              layout
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              transition={{ duration: 0.3 }}
              onClick={() => navigate(`/case/${caseItem.id}`)}
              style={{
                padding: theme.spacing.lg,
                backgroundColor: theme.colors.surface,
                borderRadius: theme.borderRadius.md,
                border: `2px solid ${
                  focusedIndex === index ? theme.colors.accent : theme.colors.border
                }`,
                cursor: 'pointer',
                transition: theme.transitions.fast,
              }}
              whileHover={{ scale: 1.02 }}
            >
              {/* Severity badge */}
              <div
                style={{
                  display: 'inline-block',
                  padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
                  borderRadius: theme.borderRadius.sm,
                  backgroundColor: getSeverityColor(caseItem.severity) + '33',
                  color: getSeverityColor(caseItem.severity),
                  fontWeight: 600,
                  fontSize: theme.typography.fontSize.xs,
                  textTransform: 'uppercase',
                  marginBottom: theme.spacing.sm,
                }}
              >
                {caseItem.severity}
              </div>
              
              {/* ID кейса */}
              <div style={{ fontWeight: 600, marginBottom: theme.spacing.sm }}>
                Кейс #{caseItem.id.slice(0, 8)}
              </div>
              
              {/* Статус */}
              <div
                style={{
                  fontSize: theme.typography.fontSize.sm,
                  color: getStatusColor(caseItem.status),
                  marginBottom: theme.spacing.sm,
                }}
              >
                {getStatusLabel(caseItem.status)}
              </div>
              
              {/* Метаданные */}
              <div
                style={{
                  fontSize: theme.typography.fontSize.xs,
                  color: theme.colors.textMuted,
                }}
              >
                Создан: {format(new Date(caseItem.created_at), 'dd.MM.yyyy HH:mm')}
              </div>
              
              {/* Находки */}
              {caseItem.findings.length > 0 && (
                <div
                  style={{
                    marginTop: theme.spacing.sm,
                    fontSize: theme.typography.fontSize.xs,
                    color: theme.colors.textSecondary,
                  }}
                >
                  Находок: {caseItem.findings.length}
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
      
      {sortedCases.length === 0 && !isLoading && (
        <div
          style={{
            textAlign: 'center',
            color: theme.colors.textMuted,
            marginTop: theme.spacing.xl,
          }}
        >
          Нет кейсов, соответствующих фильтрам
        </div>
      )}
      
      {/* Keyboard shortcuts (j/k/Enter) */}
      <KeyboardShortcuts cases={sortedCases} />
      
      {/* Подсказка */}
      <div
        style={{
          position: 'fixed',
          bottom: theme.spacing.lg,
          right: theme.spacing.lg,
          padding: theme.spacing.md,
          backgroundColor: theme.colors.surface,
          borderRadius: theme.borderRadius.md,
          fontSize: theme.typography.fontSize.xs,
          color: theme.colors.textMuted,
          border: `1px solid ${theme.colors.border}`,
        }}
      >
        <kbd style={{ padding: '2px 6px', backgroundColor: theme.colors.background, borderRadius: '3px' }}>j</kbd> / 
        <kbd style={{ padding: '2px 6px', backgroundColor: theme.colors.background, borderRadius: '3px' }}>k</kbd> — навигация,{' '}
        <kbd style={{ padding: '2px 6px', backgroundColor: theme.colors.background, borderRadius: '3px' }}>Enter</kbd> — открыть
      </div>
    </div>
  );
}

// Фильтр-чип компонент
function FilterChip({
  label,
  active,
  color,
  onClick,
}: {
  label: string;
  active: boolean;
  color: string;
  onClick: () => void;
}) {
  return (
    <motion.button
      whileTap={{ scale: 0.95 }}
      onClick={onClick}
      style={{
        padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
        backgroundColor: active ? color + '33' : 'transparent',
        color: active ? color : theme.colors.textSecondary,
        border: `1px solid ${active ? color : theme.colors.border}`,
        borderRadius: theme.borderRadius.sm,
        cursor: 'pointer',
        fontSize: theme.typography.fontSize.sm,
        fontWeight: active ? 600 : 400,
        transition: theme.transitions.fast,
      }}
    >
      {label}
    </motion.button>
  );
}
