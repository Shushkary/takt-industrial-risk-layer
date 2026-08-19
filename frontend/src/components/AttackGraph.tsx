// Граф атаки с React Flow, force-layout и анимацией цепочки

import { useCallback, useEffect, useMemo, useState } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ConnectionLineType,
  Handle,
  Position,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { motion } from 'framer-motion';
import type { AttackChain } from '../types/api';
import { theme } from '../styles/theme';
import { useCaseStore } from '../stores/caseStore';

interface AttackGraphProps {
  attackChain: AttackChain;
}

export function AttackGraph({ attackChain }: AttackGraphProps) {
  const { fitView } = useReactFlow();
  const setSelectedEntity = useCaseStore((state) => state.setSelectedEntity);
  const [playbackState, setPlaybackState] = useState<'idle' | 'playing' | 'complete'>('idle');
  const [currentStep, setCurrentStep] = useState(0);
  const [selectedEdge, setSelectedEdge] = useState<{ reason: string; step: number } | null>(null);
  
  // Преобразование данных для React Flow
  const initialNodes = useMemo<Node[]>(
    () =>
      attackChain.nodes.map((node, index) => ({
        id: node.id,
        type: 'custom',
        position: node.position || {
          x: index * 220,
          y: 120 + (index % 2) * 90,
        },
        data: {
          label: node.label,
          nodeType: node.type,
          severity: node.severity,
          icon: getIcon(node.type),
        },
      })),
    [attackChain.nodes]
  );
  
  const initialEdges = useMemo<Edge[]>(
    () =>
      attackChain.edges.map((edge, index) => ({
        id: edge.id || `edge-${index}`,
        source: edge.source,
        target: edge.target,
        label: `${index + 1}`,
        data: {
          correlationReason: edge.correlation_reason,
          correlationStep: index + 1,
        },
        type: ConnectionLineType.SmoothStep,
        animated: false,
        style: {
          stroke: theme.colors.textMuted,
          strokeWidth: 2,
          strokeDasharray: '5,5',
        },
        labelStyle: {
          fontSize: theme.typography.fontSize.xs,
          fontWeight: 700,
          fill: theme.colors.textPrimary,
        },
        labelBgStyle: {
          fill: theme.colors.surfaceElevated,
          fillOpacity: 0.96,
        },
        labelBgPadding: [6, 4],
        labelBgBorderRadius: 6,
      })),
    [attackChain.edges]
  );
  
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  
  // Синхронизация и автоматическое центрирование при смене кейса.
  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
    setPlaybackState('idle');
    setCurrentStep(0);
    setSelectedEdge(null);
    const timer = window.setTimeout(
      () => fitView({ duration: 300, padding: 0.2 }),
      100
    );
    return () => window.clearTimeout(timer);
  }, [fitView, initialEdges, initialNodes, setEdges, setNodes]);
  
  // Режим "проиграть атаку"
  useEffect(() => {
    if (playbackState !== 'playing' || nodes.length === 0) return;
    
    const timer = window.setInterval(() => {
      setCurrentStep((prev) => {
        if (prev >= nodes.length - 1) {
          setPlaybackState('complete');
          return prev;
        }
        return prev + 1;
      });
    }, 900);
    
    return () => window.clearInterval(timer);
  }, [playbackState, nodes.length]);
  
  // Подсветка узлов в playback mode
  useEffect(() => {
    if (playbackState !== 'idle') {
      setNodes((nds) =>
        nds.map((node, index) => ({
          ...node,
          data: {
            ...node.data,
            highlighted: index <= currentStep,
          },
        }))
      );
      
      setEdges((eds) =>
        eds.map((edge, index) => ({
          ...edge,
          animated: index < currentStep,
          style: {
            ...edge.style,
            stroke:
              index < currentStep ? theme.colors.accent : theme.colors.textMuted,
          },
        }))
      );
    } else {
      // Сброс подсветки
      setNodes((nds) =>
        nds.map((node) => ({
          ...node,
          data: { ...node.data, highlighted: false },
        }))
      );
      setEdges((eds) =>
        eds.map((edge) => ({
          ...edge,
          animated: false,
          style: { ...edge.style, stroke: theme.colors.textMuted },
        }))
      );
    }
  }, [playbackState, currentStep, setNodes, setEdges]);
  
  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      setSelectedEntity({
        type: node.data.nodeType as any,
        id: node.data.label,
      });
    },
    [setSelectedEntity]
  );
  
  const onEdgeClick = useCallback((_: React.MouseEvent, edge: Edge) => {
    const data = edge.data as
      | { correlationReason?: string; correlationStep?: number }
      | undefined;
    if (data?.correlationReason) {
      setSelectedEdge({
        reason: data.correlationReason,
        step: data.correlationStep ?? 1,
      });
    }
  }, []);

  const playbackReason =
    playbackState !== 'idle' && currentStep > 0
      ? attackChain.edges[Math.min(currentStep - 1, attackChain.edges.length - 1)]
          ?.correlation_reason
      : null;
  const visibleReason = playbackReason || selectedEdge?.reason;
  const visibleReasonStep = playbackReason ? currentStep : selectedEdge?.step ?? 1;
  
  return (
    <div style={{ height: '100%', position: 'relative' }}>
      {/* Тулбар */}
      <div
        style={{
          position: 'absolute',
          top: theme.spacing.md,
          left: theme.spacing.md,
          zIndex: 10,
          display: 'flex',
          gap: theme.spacing.sm,
        }}
      >
        <button
          type="button"
          aria-label={
            playbackState === 'playing'
              ? 'Остановить воспроизведение цепочки'
              : 'Проиграть цепочку событий'
          }
          disabled={nodes.length === 0}
          onClick={() => {
            if (playbackState === 'playing') {
              setPlaybackState('idle');
              setCurrentStep(0);
            } else {
              setCurrentStep(0);
              setPlaybackState('playing');
            }
          }}
          style={{
            padding: `${theme.spacing.sm} ${theme.spacing.md}`,
            backgroundColor:
              playbackState === 'playing' ? theme.colors.error : theme.colors.accent,
            color: theme.colors.textPrimary,
            border: 'none',
            borderRadius: theme.borderRadius.sm,
            cursor: nodes.length === 0 ? 'not-allowed' : 'pointer',
            fontWeight: 600,
            opacity: nodes.length === 0 ? 0.55 : 1,
          }}
        >
          {playbackState === 'playing'
            ? '■ Стоп'
            : playbackState === 'complete'
              ? '↻ Повторить цепочку'
              : '▶ Проиграть цепочку'}
        </button>
        
        {playbackState !== 'idle' && nodes.length > 0 && (
          <div
            role="status"
            aria-live="polite"
            style={{
              padding: `${theme.spacing.sm} ${theme.spacing.md}`,
              backgroundColor: theme.colors.surface,
              borderRadius: theme.borderRadius.sm,
              color: theme.colors.textPrimary,
            }}
          >
            {playbackState === 'complete' ? 'Цепочка завершена' : 'Воспроизведение'} · шаг{' '}
            {currentStep + 1} из {nodes.length}
          </div>
        )}
      </div>

      {visibleReason && (
        <div
          role="note"
          style={{
            position: 'absolute',
            top: 68,
            left: theme.spacing.md,
            zIndex: 9,
            width: 'min(430px, calc(100% - 32px))',
            padding: `${theme.spacing.sm} ${theme.spacing.md}`,
            backgroundColor: theme.colors.surfaceElevated,
            border: `1px solid ${theme.colors.border}`,
            borderRadius: theme.borderRadius.md,
            boxShadow: '0 12px 36px rgba(0, 0, 0, 0.36)',
            color: theme.colors.textSecondary,
            fontSize: theme.typography.fontSize.sm,
            lineHeight: 1.45,
          }}
        >
          <div
            style={{
              marginBottom: theme.spacing.xs,
              color: theme.colors.textMuted,
              fontSize: theme.typography.fontSize.xs,
              fontWeight: 700,
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
            }}
          >
            Причина корреляции · шаг {visibleReasonStep}
          </div>
          {visibleReason}
        </div>
      )}
      
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        nodeTypes={{ custom: CustomNode }}
        fitView
        style={{ backgroundColor: theme.colors.background }}
      >
        <Background color={theme.colors.border} gap={16} />
        <Controls />
        <MiniMap
          nodeColor={(node) => getSeverityColor((node.data as any).severity)}
          style={{ backgroundColor: theme.colors.surface }}
        />
      </ReactFlow>
    </div>
  );
}

// Кастомный узел с иконкой и цветовым кодом severity
function CustomNode({ data }: { data: any }) {
  const severityColor = getSeverityColor(data.severity);
  const isHighlighted = data.highlighted;
  
  return (
    <motion.div
      animate={{
        scale: isHighlighted ? 1.2 : 1,
        borderColor: isHighlighted ? theme.colors.accent : severityColor,
      }}
      transition={{ duration: 0.3 }}
      style={{
        padding: theme.spacing.md,
        borderRadius: theme.borderRadius.md,
        backgroundColor: theme.colors.surface,
        border: `3px solid ${severityColor}`,
        minWidth: '120px',
        textAlign: 'center',
        boxShadow: isHighlighted ? `0 0 20px ${theme.colors.accent}` : 'none',
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{
          width: 9,
          height: 9,
          backgroundColor: theme.colors.textMuted,
          border: `2px solid ${theme.colors.surface}`,
        }}
      />
      <div style={{ fontSize: '24px', marginBottom: theme.spacing.xs }}>
        {data.icon}
      </div>
      <div
        style={{
          fontSize: theme.typography.fontSize.sm,
          fontWeight: 600,
          color: theme.colors.textPrimary,
          wordBreak: 'break-all',
        }}
      >
        {data.label}
      </div>
      <div
        style={{
          fontSize: theme.typography.fontSize.xs,
          color: theme.colors.textMuted,
          marginTop: theme.spacing.xs,
        }}
      >
        {data.nodeType}
      </div>
      <Handle
        type="source"
        position={Position.Right}
        style={{
          width: 9,
          height: 9,
          backgroundColor: theme.colors.accent,
          border: `2px solid ${theme.colors.surface}`,
        }}
      />
    </motion.div>
  );
}

// Вспомогательные функции
function getIcon(type: string): string {
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
}

function getSeverityColor(severity?: string): string {
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
}
