// Граф атаки с React Flow, force-layout и анимацией цепочки

import { useCallback, useEffect, useState } from 'react';
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
  const [playbackMode, setPlaybackMode] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  
  // Преобразование данных для React Flow
  const initialNodes: Node[] = attackChain.nodes.map((node) => ({
    id: node.id,
    type: 'custom',
    position: node.position || { x: Math.random() * 500, y: Math.random() * 500 },
    data: {
      label: node.label,
      nodeType: node.type,
      severity: node.severity,
      icon: getIcon(node.type),
    },
  }));
  
  const initialEdges: Edge[] = attackChain.edges.map((edge, index) => ({
    id: edge.id || `edge-${index}`,
    source: edge.source,
    target: edge.target,
    label: edge.correlation_reason,
    type: ConnectionLineType.SmoothStep,
    animated: false,
    style: {
      stroke: theme.colors.textMuted,
      strokeWidth: 2,
      strokeDasharray: '5,5',
    },
    labelStyle: {
      fontSize: theme.typography.fontSize.xs,
      fill: theme.colors.textSecondary,
    },
  }));
  
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  
  // Автоматическое центрирование при загрузке
  useEffect(() => {
    setTimeout(() => fitView({ duration: 300 }), 100);
  }, [fitView]);
  
  // Режим "проиграть атаку"
  useEffect(() => {
    if (!playbackMode) return;
    
    const timer = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev >= nodes.length - 1) {
          setPlaybackMode(false);
          return 0;
        }
        return prev + 1;
      });
    }, 500); // 500 мс на шаг
    
    return () => clearInterval(timer);
  }, [playbackMode, nodes.length]);
  
  // Подсветка узлов в playback mode
  useEffect(() => {
    if (playbackMode) {
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
  }, [playbackMode, currentStep, setNodes, setEdges]);
  
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
    alert(`Причина корреляции:\n${edge.label}`);
  }, []);
  
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
          onClick={() => {
            setPlaybackMode(!playbackMode);
            if (!playbackMode) setCurrentStep(0);
          }}
          style={{
            padding: `${theme.spacing.sm} ${theme.spacing.md}`,
            backgroundColor: playbackMode ? theme.colors.error : theme.colors.accent,
            color: theme.colors.textPrimary,
            border: 'none',
            borderRadius: theme.borderRadius.sm,
            cursor: 'pointer',
            fontWeight: 600,
          }}
        >
          {playbackMode ? '⏹ Стоп' : '▶️ Проиграть атаку'}
        </button>
        
        {playbackMode && (
          <div
            style={{
              padding: `${theme.spacing.sm} ${theme.spacing.md}`,
              backgroundColor: theme.colors.surface,
              borderRadius: theme.borderRadius.sm,
              color: theme.colors.textPrimary,
            }}
          >
            Шаг {currentStep + 1} / {nodes.length}
          </div>
        )}
      </div>
      
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
