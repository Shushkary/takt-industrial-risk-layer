import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { format } from 'date-fns';
import { fetchCases, subscribeToUpdates } from '../api/client';
import { KeyboardShortcuts } from '../components/KeyboardShortcuts';
import { useCaseStore } from '../stores/caseStore';
import { theme } from '../styles/theme';
import type { Case } from '../types/api';

const severityMeta: Record<Case['severity'], { label: string; code: string; color: string }> = {
  critical: { label: 'Критический', code: 'Critical', color: theme.colors.critical },
  high: { label: 'Высокий', code: 'High', color: theme.colors.high },
  medium: { label: 'Средний', code: 'Medium', color: theme.colors.medium },
  low: { label: 'Низкий', code: 'Low', color: theme.colors.low },
};

const statusMeta: Record<Case['status'], { label: string; color: string }> = {
  new: { label: 'Новый', color: theme.colors.new },
  investigating: { label: 'В работе', color: theme.colors.investigating },
  resolved: { label: 'Закрыт', color: theme.colors.resolved },
};

export function IncidentQueue() {
  const navigate = useNavigate();
  const reduceMotion = useReducedMotion();
  const {
    filters,
    toggleSeverityFilter,
    toggleStatusFilter,
    clearFilters,
    focusedIndex,
  } = useCaseStore();
  const [liveCases, setLiveCases] = useState<Case[]>([]);

  const { data: initialCases, isLoading } = useQuery({
    queryKey: ['cases'],
    queryFn: fetchCases,
  });

  useEffect(() => {
    return subscribeToUpdates((updatedCase) => {
      setLiveCases((previous) => {
        const index = previous.findIndex((item) => item.id === updatedCase.id);
        if (index < 0) return [updatedCase, ...previous];
        const next = [...previous];
        next[index] = updatedCase;
        return next;
      });
    });
  }, []);

  const allCases = useMemo(() => {
    const byId = new Map((initialCases ?? []).map((item) => [item.id, item]));
    liveCases.forEach((item) => byId.set(item.id, item));
    return Array.from(byId.values());
  }, [initialCases, liveCases]);
  const sortedCases = useMemo(() => {
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    return allCases
      .filter((item) => {
        if (filters.severity && !filters.severity.includes(item.severity)) return false;
        if (filters.status && !filters.status.includes(item.status)) return false;
        return true;
      })
      .sort((a, b) => {
        const bySeverity = severityOrder[b.severity] - severityOrder[a.severity];
        return bySeverity || new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      });
  }, [allCases, filters]);

  const criticalCount = allCases.filter((item) => item.severity === 'critical').length;
  const activeCount = allCases.filter((item) => item.status === 'investigating').length;
  const newCount = allCases.filter((item) => item.status === 'new').length;

  return (
    <main className="app-frame">
      <AppChrome />

      <header className="page-hero">
        <div>
          <div className="eyebrow">Industrial SOC · incident triage</div>
          <h1 className="page-title">Очередь инцидентов</h1>
          <p className="page-lede">
            Приоритизация событий промышленного сегмента по контекстному риску,
            корреляции и влиянию на технологический процесс.
          </p>
        </div>
        <a
          className="primary-link"
          href={`${import.meta.env.BASE_URL}compare`}
          onClick={(event) => {
            event.preventDefault();
            navigate('/compare');
          }}
        >
          Сравнить режимы <span aria-hidden="true">→</span>
        </a>
      </header>

      <section className="summary-grid" aria-label="Сводка очереди">
        <SummaryItem label="Всего кейсов" value={String(allCases.length)} note="Синтетический стенд" />
        <SummaryItem label="Критические" value={String(criticalCount)} note="Требуют немедленного triage" color={theme.colors.critical} />
        <SummaryItem label="В работе" value={String(activeCount)} note="Назначены оператору" color={theme.colors.investigating} />
        <SummaryItem label="Новые" value={String(newCount)} note="SSE-поток активен" color={theme.colors.accent} />
      </section>

      <section className="filter-panel" aria-label="Фильтры очереди">
        <div className="filter-group">
          <span className="filter-label">Серьёзность</span>
          {(Object.keys(severityMeta) as Case['severity'][]).map((severity) => (
            <FilterChip
              key={severity}
              label={severityMeta[severity].label}
              active={filters.severity?.includes(severity) ?? false}
              color={severityMeta[severity].color}
              onClick={() => toggleSeverityFilter(severity)}
            />
          ))}
        </div>

        <div className="filter-group">
          <span className="filter-label">Состояние</span>
          {(Object.keys(statusMeta) as Case['status'][]).map((status) => (
            <FilterChip
              key={status}
              label={statusMeta[status].label}
              active={filters.status?.includes(status) ?? false}
              color={statusMeta[status].color}
              onClick={() => toggleStatusFilter(status)}
            />
          ))}
        </div>

        {(filters.severity || filters.status) && (
          <button className="filter-reset" type="button" onClick={clearFilters}>
            Сбросить фильтры
          </button>
        )}
      </section>

      {isLoading && <div className="empty-state">Загрузка очереди…</div>}

      <section className="incident-grid" aria-label="Кейсы">
        <AnimatePresence>
          {sortedCases.map((item, index) => {
            const severity = severityMeta[item.severity];
            const status = statusMeta[item.status];
            const risk = Math.round(item.risk_score * 100);

            return (
              <motion.button
                className={`incident-card${focusedIndex === index ? ' is-focused' : ''}`}
                key={item.id}
                type="button"
                layout={!reduceMotion}
                initial={reduceMotion ? false : { opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={reduceMotion ? undefined : { opacity: 0, y: -6 }}
                whileHover={reduceMotion ? undefined : { y: -2 }}
                transition={{ duration: 0.2 }}
                onClick={() => navigate(`/case/${item.id}`)}
                aria-label={`${severity.label}: ${item.title}. Риск ${risk} из 100`}
                style={{
                  '--severity-color': severity.color,
                  '--risk-width': `${risk}%`,
                } as React.CSSProperties}
              >
                <div className="incident-card-top">
                  <span
                    className="severity-pill"
                    style={{ '--severity-color': severity.color } as React.CSSProperties}
                  >
                    {severity.code}
                  </span>
                  <span className="risk-score">TAKT Risk <strong>{risk}</strong>/100</span>
                </div>

                <h2 className="incident-title">{item.title}</h2>
                <div className="incident-id">{item.id}</div>
                <div className="risk-track" aria-hidden="true"><span /></div>

                <div className="incident-meta">
                  <span
                    className="status-pill"
                    style={{ '--status-color': status.color } as React.CSSProperties}
                  >
                    {status.label}
                  </span>
                  <span>{format(new Date(item.updated_at), 'dd.MM · HH:mm')}</span>
                </div>

                <div className="incident-meta" style={{ marginTop: 10 }}>
                  <span>{item.findings.length ? `${item.findings.length} находок` : 'Находок нет'}</span>
                  <span>{item.severity === 'critical' ? 'MITRE ATT&CK for ICS' : 'Правило SIEM'}</span>
                </div>
              </motion.button>
            );
          })}
        </AnimatePresence>
      </section>

      {sortedCases.length === 0 && !isLoading && (
        <div className="empty-state">По выбранным фильтрам кейсов нет.</div>
      )}

      <KeyboardShortcuts cases={sortedCases} />

      <footer className="queue-footer">
        <span>TAKT PT · демонстрационная среда · IEC 60870-5-104</span>
        <span><kbd>J</kbd> <kbd>K</kbd> навигация · <kbd>Enter</kbd> открыть кейс</span>
      </footer>
    </main>
  );
}

function AppChrome() {
  return (
    <div className="app-chrome">
      <div className="brand-lockup">
        <div className="brand-mark" aria-hidden="true">T</div>
        <div>
          <div className="brand-name">TAKT Industrial Risk Layer</div>
          <div className="brand-caption">Operator workspace</div>
        </div>
      </div>
      <div className="system-state"><span>Стенд работает</span></div>
    </div>
  );
}

function SummaryItem({
  label,
  value,
  note,
  color,
}: {
  label: string;
  value: string;
  note: string;
  color?: string;
}) {
  return (
    <div className="summary-item">
      <div className="summary-label">{label}</div>
      <div className="summary-value" style={color ? { color } : undefined}>{value}</div>
      <div className="summary-note">{note}</div>
    </div>
  );
}

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
    <button
      className="filter-chip"
      type="button"
      aria-pressed={active}
      onClick={onClick}
      style={{ '--chip-color': color } as React.CSSProperties}
    >
      {label}
    </button>
  );
}
