// Таймлайн событий с zoom/brush (visx)

import { useMemo, useState } from 'react';
import { scaleTime, scaleLinear } from '@visx/scale';
import { AxisBottom } from '@visx/axis';
import { Brush } from '@visx/brush';
import { Bounds } from '@visx/brush/lib/types';
import { Group } from '@visx/group';
import type { Event } from '../types/api';
import { theme } from '../styles/theme';
import { useCaseStore } from '../stores/caseStore';

interface TimelineProps {
  events: Event[];
  width?: number;
  height?: number;
}

export function Timeline({ events, width = 800, height = 400 }: TimelineProps) {
  const setSelectedEntity = useCaseStore((state) => state.setSelectedEntity);
  const [brushBounds, setBrushBounds] = useState<Bounds | null>(null);
  
  // Группировка событий по source_class (дорожки)
  const lanes = useMemo(() => {
    const laneMap = new Map<string, Event[]>();
    events.forEach((event) => {
      if (!laneMap.has(event.source_class)) {
        laneMap.set(event.source_class, []);
      }
      laneMap.get(event.source_class)!.push(event);
    });
    return Array.from(laneMap.entries());
  }, [events]);
  
  if (events.length === 0) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100%',
          color: theme.colors.textMuted,
        }}
      >
        Нет событий для отображения
      </div>
    );
  }
  
  const safeWidth = Math.max(width, 640);
  const margin = { top: 58, right: 36, bottom: 30, left: 120 };
  const innerWidth = safeWidth - margin.left - margin.right;
  const brushHeight = 52;
  const availableHeight = Math.max(180, height - 220);
  const overviewHeight = Math.min(Math.max(lanes.length * 68, 180), Math.min(420, availableHeight));
  const svgHeight = margin.top + overviewHeight + brushHeight + 78;
  
  // Временные границы
  const firstTimestamp = Math.min(...events.map((e) => new Date(e.ts).getTime()));
  const lastTimestamp = Math.max(...events.map((e) => new Date(e.ts).getTime()));
  const timePadding = Math.max((lastTimestamp - firstTimestamp) * 0.06, 30_000);
  const timeExtent: [number, number] = [
    firstTimestamp - timePadding,
    lastTimestamp + timePadding,
  ];
  const eventNumbers = new Map(
    [...events]
      .sort((left, right) => new Date(left.ts).getTime() - new Date(right.ts).getTime())
      .map((event, index) => [event.id, index + 1])
  );
  
  // Шкалы для overview
  const xScaleOverview = scaleTime({
    domain: timeExtent,
    range: [0, innerWidth],
  });
  
  const yScaleOverview = scaleLinear({
    domain: [0, lanes.length],
    range: [0, overviewHeight],
  });
  
  // Шкалы для zoom view (с учётом brush)
  const zoomDomain = brushBounds
    ? [brushBounds.x0, brushBounds.x1].map((x) => xScaleOverview.invert(x).getTime())
    : timeExtent;
  
  const xScaleZoom = scaleTime({
    domain: zoomDomain,
    range: [0, innerWidth],
  });
  
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
  
  const handleEventClick = (event: Event) => {
    // Приоритет: host_id > user_id > process > address
    if (event.host_id) {
      setSelectedEntity({ type: 'host', id: event.host_id });
    } else if (event.user_id) {
      setSelectedEntity({ type: 'user', id: event.user_id });
    } else if (event.process) {
      setSelectedEntity({ type: 'process', id: event.process });
    } else if (event.address) {
      setSelectedEntity({ type: 'address', id: event.address });
    }
  };
  
  return (
    <div
      style={{
        overflowX: 'auto',
        backgroundColor: theme.colors.background,
        height: '100%',
      }}
    >
      <svg width={safeWidth} height={svgHeight} role="img" aria-label={`Таймлайн: ${events.length} событий`}>
        <text
          x={margin.left}
          y={22}
          fontSize={theme.typography.fontSize.md}
          fontWeight={700}
          fill={theme.colors.textPrimary}
        >
          Цепочка событий
        </text>
        <text
          x={margin.left}
          y={43}
          fontSize={theme.typography.fontSize.xs}
          fill={theme.colors.textMuted}
        >
          {events.length} событий · {lanes.length} источников ·{' '}
          {new Date(firstTimestamp).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}
          {' — '}
          {new Date(lastTimestamp).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}
        </text>
        <Group left={margin.left} top={margin.top}>
          {/* Zoom View */}
          <Group>
            {/* Дорожки */}
            {lanes.map(([sourceClass, laneEvents], laneIndex) => (
              <Group key={sourceClass} top={yScaleOverview(laneIndex)}>
                <line
                  x1={0}
                  x2={innerWidth}
                  y1={yScaleOverview(1) / 2}
                  y2={yScaleOverview(1) / 2}
                  stroke={theme.colors.border}
                  strokeWidth={1}
                  opacity={0.65}
                />
                {/* Подпись дорожки */}
                <text
                  x={-10}
                  y={yScaleOverview(1) / 2}
                  textAnchor="end"
                  fontSize={theme.typography.fontSize.xs}
                  fill={theme.colors.textSecondary}
                  dominantBaseline="middle"
                >
                  {sourceClass}
                </text>
                
                {/* События на дорожке */}
                {laneEvents
                  .filter((e) => {
                    const ts = new Date(e.ts).getTime();
                    return ts >= zoomDomain[0] && ts <= zoomDomain[1];
                  })
                  .map((event) => {
                    const x = xScaleZoom(new Date(event.ts));
                    const y = yScaleOverview(1) / 2;
                    
                    return (
                      <Group
                        key={event.id}
                        left={x}
                        top={y}
                        style={{ cursor: 'pointer' }}
                        onClick={() => handleEventClick(event)}
                      >
                        <circle
                          r={8}
                          fill={getSeverityColor(event.severity)}
                          stroke={theme.colors.background}
                          strokeWidth={3}
                        >
                          <title>{`${event.source_class} — ${new Date(event.ts).toLocaleString('ru-RU')}`}</title>
                        </circle>
                        <text
                          x={13}
                          y={4}
                          fontSize={theme.typography.fontSize.xs}
                          fontWeight={700}
                          fill={theme.colors.textPrimary}
                        >
                          #{eventNumbers.get(event.id)}
                        </text>
                      </Group>
                    );
                  })}
              </Group>
            ))}
            
            {/* Оси */}
            <AxisBottom
              top={overviewHeight}
              scale={xScaleZoom}
              stroke={theme.colors.border}
              tickStroke={theme.colors.border}
              tickLabelProps={() => ({
                fill: theme.colors.textSecondary,
                fontSize: theme.typography.fontSize.xs,
                textAnchor: 'middle',
              })}
            />
          </Group>
          
          {/* Brush (overview с выделением) */}
          <Group top={overviewHeight + 44}>
            <rect
              width={innerWidth}
              height={brushHeight}
              fill={theme.colors.surface}
              rx={theme.borderRadius.sm}
            />
            
            {/* Мини-карта событий */}
            {lanes.map(([sourceClass, laneEvents], laneIndex) => (
              <Group key={`mini-${sourceClass}`}>
                {laneEvents.map((event) => {
                  const x = xScaleOverview(new Date(event.ts));
                  const y = (laneIndex / lanes.length) * brushHeight;
                  
                  return (
                    <line
                      key={`mini-${event.id}`}
                      x1={x}
                      x2={x}
                      y1={y}
                      y2={y + brushHeight / lanes.length}
                      stroke={getSeverityColor(event.severity)}
                      strokeWidth={1}
                      opacity={0.6}
                    />
                  );
                })}
              </Group>
            ))}
            
            <Brush
              xScale={xScaleOverview}
              yScale={scaleLinear({ domain: [0, 1], range: [0, brushHeight] })}
              width={innerWidth}
              height={brushHeight}
              handleSize={8}
              resizeTriggerAreas={['left', 'right']}
              brushDirection="horizontal"
              onChange={(domain) => {
                if (domain) {
                  setBrushBounds(domain as Bounds);
                }
              }}
              selectedBoxStyle={{
                fill: theme.colors.accent,
                fillOpacity: 0.2,
                stroke: theme.colors.accent,
                strokeWidth: 2,
              }}
            />
          </Group>
        </Group>
      </svg>
    </div>
  );
}
