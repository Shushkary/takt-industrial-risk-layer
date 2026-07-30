// Карточка выбранной сущности с sparkline типичности

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { LinePath } from '@visx/shape';
import { scaleLinear } from '@visx/scale';
import { motion } from 'framer-motion';
import { fetchEntityBaseline, addFinding } from '../api/client';
import { useCaseStore } from '../stores/caseStore';
import { theme } from '../styles/theme';

export function EntityCard({ caseId }: { caseId?: string }) {
  const selectedEntity = useCaseStore((state) => state.selectedEntity);
  const queryClient = useQueryClient();
  
  const { data: baseline, isLoading } = useQuery({
    queryKey: ['baseline', selectedEntity?.type, selectedEntity?.id],
    queryFn: () =>
      selectedEntity
        ? fetchEntityBaseline(selectedEntity.type, selectedEntity.id)
        : Promise.resolve(null),
    enabled: !!selectedEntity,
  });
  
  const addFindingMutation = useMutation({
    mutationFn: () => {
      if (!caseId || !selectedEntity) throw new Error('Нет выбранной сущности');
      return addFinding(caseId, selectedEntity.type, selectedEntity.id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case', caseId] });
      alert('Находка добавлена в кейс');
    },
    onError: (error) => {
      alert(`Ошибка: ${error.message}`);
    },
  });
  
  if (!selectedEntity) {
    return (
      <div
        style={{
          padding: theme.spacing.lg,
          color: theme.colors.textMuted,
          textAlign: 'center',
        }}
      >
        Выберите узел в графе или событие в таймлайне
      </div>
    );
  }
  
  // Иконки по типу сущности
  const getIcon = (type: string) => {
    switch (type) {
      case 'host':
        return '🖥️';
      case 'user':
        return '👤';
      case 'process':
        return '⚙️';
      case 'address':
        return '🌐';
      case 'artifact':
        return '📄';
      default:
        return '•';
    }
  };
  
  const getTypeLabel = (type: string) => {
    switch (type) {
      case 'host':
        return 'Хост';
      case 'user':
        return 'Пользователь';
      case 'process':
        return 'Процесс';
      case 'address':
        return 'Адрес';
      case 'artifact':
        return 'Артефакт';
      default:
        return type;
    }
  };
  
  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3 }}
      style={{
        padding: theme.spacing.lg,
        backgroundColor: theme.colors.surface,
        borderRadius: theme.borderRadius.md,
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        gap: theme.spacing.md,
      }}
    >
      {/* Заголовок */}
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.sm }}>
        <span style={{ fontSize: '24px' }}>{getIcon(selectedEntity.type)}</span>
        <div>
          <div style={{ fontSize: theme.typography.fontSize.sm, color: theme.colors.textSecondary }}>
            {getTypeLabel(selectedEntity.type)}
          </div>
          <div style={{ fontWeight: 600, wordBreak: 'break-all' }}>{selectedEntity.id}</div>
        </div>
      </div>
      
      {/* Sparkline типичности */}
      {isLoading && <div style={{ color: theme.colors.textMuted }}>Загрузка baseline...</div>}
      
      {baseline && baseline.z_scores.length > 0 && (
        <div>
          <div
            style={{
              fontSize: theme.typography.fontSize.sm,
              color: theme.colors.textSecondary,
              marginBottom: theme.spacing.sm,
            }}
          >
            Типичность (z-score)
          </div>
          <Sparkline data={baseline.z_scores} width={240} height={60} />
          <div
            style={{
              fontSize: theme.typography.fontSize.xs,
              color: theme.colors.textMuted,
              marginTop: theme.spacing.xs,
            }}
          >
            Среднее: {baseline.mean.toFixed(2)} ± {baseline.stddev.toFixed(2)}
          </div>
        </div>
      )}
      
      {/* Кнопка добавления находки */}
      {caseId && (
        <button
          onClick={() => addFindingMutation.mutate()}
          disabled={addFindingMutation.isPending}
          style={{
            marginTop: 'auto',
            padding: `${theme.spacing.sm} ${theme.spacing.md}`,
            backgroundColor: theme.colors.accent,
            color: theme.colors.textPrimary,
            border: 'none',
            borderRadius: theme.borderRadius.sm,
            cursor: addFindingMutation.isPending ? 'not-allowed' : 'pointer',
            fontWeight: 600,
            transition: theme.transitions.fast,
            opacity: addFindingMutation.isPending ? 0.6 : 1,
          }}
          onMouseEnter={(e) => {
            if (!addFindingMutation.isPending) {
              e.currentTarget.style.backgroundColor = theme.colors.accentHover;
            }
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = theme.colors.accent;
          }}
        >
          {addFindingMutation.isPending ? 'Добавление...' : 'Добавить в находки'}
        </button>
      )}
    </motion.div>
  );
}

// Sparkline компонент для отрисовки z-score
function Sparkline({ data, width, height }: { data: number[]; width: number; height: number }) {
  const xScale = scaleLinear({
    domain: [0, data.length - 1],
    range: [0, width],
  });
  
  const yScale = scaleLinear({
    domain: [Math.min(...data, -2), Math.max(...data, 2)],
    range: [height, 0],
  });
  
  return (
    <svg width={width} height={height}>
      {/* Нулевая линия */}
      <line
        x1={0}
        x2={width}
        y1={yScale(0)}
        y2={yScale(0)}
        stroke={theme.colors.textMuted}
        strokeWidth={1}
        strokeDasharray="2,2"
      />
      
      {/* Линия z-score */}
      <LinePath
        data={data}
        x={(_d, i) => xScale(i)}
        y={(d) => yScale(d)}
        stroke={theme.colors.accent}
        strokeWidth={2}
      />
      
      {/* Точки */}
      {data.map((value, i) => (
        <circle
          key={i}
          cx={xScale(i)}
          cy={yScale(value)}
          r={3}
          fill={Math.abs(value) > 2 ? theme.colors.warning : theme.colors.accent}
        />
      ))}
    </svg>
  );
}
