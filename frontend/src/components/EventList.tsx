// Список событий в табличном виде

import { format } from 'date-fns';
import { motion } from 'framer-motion';
import type { Event } from '../types/api';
import { theme } from '../styles/theme';
import { useCaseStore } from '../stores/caseStore';

interface EventListProps {
  events: Event[];
}

export function EventList({ events }: EventListProps) {
  const setSelectedEntity = useCaseStore((state) => state.setSelectedEntity);
  
  const getSeverityColor = (severity: Event['severity']) => {
    switch (severity) {
      case 'critical':
        return theme.colors.critical;
      case 'high':
        return theme.colors.high;
      case 'medium':
        return theme.colors.medium;
      case 'low':
        return theme.colors.low;
      default:
        return theme.colors.textSecondary;
    }
  };
  
  const handleEntityClick = (
    type: 'host' | 'user' | 'process' | 'address' | 'artifact',
    id: string
  ) => {
    setSelectedEntity({ type, id });
  };
  
  return (
    <div
      style={{
        overflowY: 'auto',
        height: '100%',
        backgroundColor: theme.colors.background,
      }}
    >
      <table
        style={{
          width: '100%',
          borderCollapse: 'collapse',
          fontSize: theme.typography.fontSize.sm,
        }}
      >
        <thead
          style={{
            position: 'sticky',
            top: 0,
            backgroundColor: theme.colors.surface,
            zIndex: 1,
          }}
        >
          <tr>
            <th style={headerStyle}>Время</th>
            <th style={headerStyle}>Источник</th>
            <th style={headerStyle}>Хост</th>
            <th style={headerStyle}>Пользователь</th>
            <th style={headerStyle}>Процесс</th>
            <th style={headerStyle}>Адрес</th>
            <th style={headerStyle}>Severity</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, index) => (
            <motion.tr
              key={event.id}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: index * 0.02, duration: 0.2 }}
              style={{
                borderBottom: `1px solid ${theme.colors.border}`,
              }}
            >
              <td style={cellStyle}>
                {format(new Date(event.ts), 'HH:mm:ss')}
                <br />
                <span style={{ fontSize: theme.typography.fontSize.xs, color: theme.colors.textMuted }}>
                  {format(new Date(event.ts), 'dd.MM.yyyy')}
                </span>
              </td>
              <td style={cellStyle}>{event.source_class}</td>
              <td style={cellStyle}>
                {event.host_id ? (
                  <button
                    onClick={() => handleEntityClick('host', event.host_id!)}
                    style={entityButtonStyle}
                  >
                    {event.host_id}
                  </button>
                ) : (
                  '—'
                )}
              </td>
              <td style={cellStyle}>
                {event.user_id ? (
                  <button
                    onClick={() => handleEntityClick('user', event.user_id!)}
                    style={entityButtonStyle}
                  >
                    {event.user_id}
                  </button>
                ) : (
                  '—'
                )}
              </td>
              <td style={cellStyle}>
                {event.process ? (
                  <button
                    onClick={() => handleEntityClick('process', event.process!)}
                    style={entityButtonStyle}
                  >
                    {event.process}
                  </button>
                ) : (
                  '—'
                )}
              </td>
              <td style={cellStyle}>
                {event.address ? (
                  <button
                    onClick={() => handleEntityClick('address', event.address!)}
                    style={entityButtonStyle}
                  >
                    {event.address}
                  </button>
                ) : (
                  '—'
                )}
              </td>
              <td style={cellStyle}>
                <span
                  style={{
                    display: 'inline-block',
                    padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
                    borderRadius: theme.borderRadius.sm,
                    backgroundColor: getSeverityColor(event.severity) + '33',
                    color: getSeverityColor(event.severity),
                    fontWeight: 600,
                    fontSize: theme.typography.fontSize.xs,
                    textTransform: 'uppercase',
                  }}
                >
                  {event.severity}
                </span>
              </td>
            </motion.tr>
          ))}
        </tbody>
      </table>
      
      {events.length === 0 && (
        <div
          style={{
            padding: theme.spacing.xl,
            textAlign: 'center',
            color: theme.colors.textMuted,
          }}
        >
          Нет событий для отображения
        </div>
      )}
    </div>
  );
}

const headerStyle: React.CSSProperties = {
  padding: theme.spacing.md,
  textAlign: 'left',
  fontWeight: 600,
  color: theme.colors.textSecondary,
  borderBottom: `2px solid ${theme.colors.border}`,
};

const cellStyle: React.CSSProperties = {
  padding: theme.spacing.md,
  color: theme.colors.textPrimary,
};

const entityButtonStyle: React.CSSProperties = {
  background: 'transparent',
  border: 'none',
  color: theme.colors.accent,
  cursor: 'pointer',
  textDecoration: 'underline',
  fontFamily: 'inherit',
  fontSize: 'inherit',
  padding: 0,
};
