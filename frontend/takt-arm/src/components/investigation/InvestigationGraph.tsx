import { useEffect, useMemo, useRef, useState } from 'react'
import type { InvestigationGraphEdge, InvestigationGraphNode } from '../../investigation/types'
import { NODE_KIND_LABELS } from '../../investigation/types'

/**
 * Граф связей расследования (ТЗ п. 5.4) с силовой раскладкой.
 *
 * Раскладка считается на месте: маленькие графы инцидента (десятки узлов) не требуют
 * внешней библиотеки, а собственная симуляция позволяет остановить анимацию по
 * `prefers-reduced-motion` и не тянуть в бандл лишние зависимости.
 */

export type GraphSelection = { id: string; type: string; value: string } | null

type Props = {
  nodes: InvestigationGraphNode[]
  edges: InvestigationGraphEdge[]
  /** Событиям вне набора соответствуют «ещё не проигранные» рёбра — они приглушены. */
  activeEventIds: Set<string>
  selectedId: string | null
  onSelect: (selection: GraphSelection) => void
  height?: number
}

type Simulated = InvestigationGraphNode & { x: number; y: number; vx: number; vy: number; degree: number }

const NODE_COLORS: Record<string, string> = {
  host: '#38bdf8',
  user: '#a78bfa',
  process: '#2dd4bf',
  address: '#94a3b8',
  hash: '#f59e0b',
  file: '#f59e0b',
  domain: '#fb7185',
  url: '#fb7185',
  account: '#a78bfa',
}

const WIDTH = 760
const CHARGE = -2600
const SPRING = 0.035
const DAMPING = 0.86
const CENTER_PULL = 0.012
const NODE_PADDING = 26

function nodeColor(type: string): string {
  return NODE_COLORS[type] ?? '#64748b'
}

function nodeRadius(node: Simulated): number {
  return 9 + Math.min(node.degree, 6) * 1.6
}

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false
  }
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

/** Один шаг силовой раскладки: отталкивание всех пар, пружины рёбер, стягивание к центру. */
function step(nodes: Simulated[], links: Array<[number, number]>, height: number, alpha: number): void {
  const cx = WIDTH / 2
  const cy = height / 2

  for (let i = 0; i < nodes.length; i += 1) {
    for (let j = i + 1; j < nodes.length; j += 1) {
      const a = nodes[i]
      const b = nodes[j]
      let dx = b.x - a.x
      let dy = b.y - a.y
      let distanceSquared = dx * dx + dy * dy
      if (distanceSquared < 1) {
        dx = (i - j) * 0.7 + 0.5
        dy = (j - i) * 0.5 + 0.5
        distanceSquared = dx * dx + dy * dy
      }
      const force = (CHARGE * alpha) / distanceSquared
      const distance = Math.sqrt(distanceSquared)
      const fx = (dx / distance) * force
      const fy = (dy / distance) * force
      a.vx += fx
      a.vy += fy
      b.vx -= fx
      b.vy -= fy
    }
  }

  for (const [from, to] of links) {
    const a = nodes[from]
    const b = nodes[to]
    const dx = b.x - a.x
    const dy = b.y - a.y
    const distance = Math.max(Math.sqrt(dx * dx + dy * dy), 1)
    const desired = 132
    const force = (distance - desired) * SPRING * alpha
    const fx = (dx / distance) * force
    const fy = (dy / distance) * force
    a.vx += fx
    a.vy += fy
    b.vx -= fx
    b.vy -= fy
  }

  for (const node of nodes) {
    node.vx += (cx - node.x) * CENTER_PULL * alpha
    node.vy += (cy - node.y) * CENTER_PULL * alpha
    node.vx *= DAMPING
    node.vy *= DAMPING
    node.x += node.vx
    node.y += node.vy
    node.x = Math.min(WIDTH - 40, Math.max(40, node.x))
    node.y = Math.min(height - 30, Math.max(30, node.y))
  }

  // Разведение перекрытий: без него круги налезают друг на друга, и клик по узлу
  // попадает в соседний — граф становится некликабельным.
  for (let pass = 0; pass < 2; pass += 1) {
    for (let i = 0; i < nodes.length; i += 1) {
      for (let j = i + 1; j < nodes.length; j += 1) {
        const a = nodes[i]
        const b = nodes[j]
        const minimum = nodeRadius(a) + nodeRadius(b) + NODE_PADDING
        let dx = b.x - a.x
        let dy = b.y - a.y
        let distance = Math.sqrt(dx * dx + dy * dy)
        if (distance >= minimum) {
          continue
        }
        if (distance < 0.001) {
          dx = (i % 2 === 0 ? 1 : -1) * 0.6
          dy = (j % 2 === 0 ? 1 : -1) * 0.6
          distance = Math.sqrt(dx * dx + dy * dy)
        }
        const shift = (minimum - distance) / 2
        const ux = (dx / distance) * shift
        const uy = (dy / distance) * shift
        a.x -= ux
        a.y -= uy
        b.x += ux
        b.y += uy
      }
    }
  }
}

export function InvestigationGraph({
  nodes,
  edges,
  activeEventIds,
  selectedId,
  onSelect,
  height = 420,
}: Props) {
  const [, setTick] = useState(0)
  const frameRef = useRef<number | null>(null)
  const simulationRef = useRef<Simulated[]>([])
  const [hovered, setHovered] = useState<string | null>(null)

  const linkIndexes = useMemo(() => {
    const index = new Map(nodes.map((node, position) => [node.id, position]))
    const pairs: Array<[number, number]> = []
    for (const edge of edges) {
      const from = index.get(edge.source)
      const to = index.get(edge.target)
      if (from !== undefined && to !== undefined && from !== to) {
        pairs.push([from, to])
      }
    }
    return pairs
  }, [nodes, edges])

  const degrees = useMemo(() => {
    const counter = new Map<string, number>()
    for (const edge of edges) {
      counter.set(edge.source, (counter.get(edge.source) ?? 0) + 1)
      counter.set(edge.target, (counter.get(edge.target) ?? 0) + 1)
    }
    return counter
  }, [edges])

  useEffect(() => {
    // Стартовая раскладка по окружности: детерминированно и без наложений в центре.
    simulationRef.current = nodes.map((node, index) => {
      const angle = (index / Math.max(nodes.length, 1)) * Math.PI * 2
      const radius = Math.min(WIDTH, height) * 0.32
      return {
        ...node,
        x: WIDTH / 2 + Math.cos(angle) * radius,
        y: height / 2 + Math.sin(angle) * radius,
        vx: 0,
        vy: 0,
        degree: degrees.get(node.id) ?? 0,
      }
    })

    const reduced = prefersReducedMotion()
    if (reduced) {
      let alpha = 1
      for (let i = 0; i < 220; i += 1) {
        step(simulationRef.current, linkIndexes, height, alpha)
        alpha *= 0.97
      }
      setTick((value) => value + 1)
      return
    }

    let alpha = 1
    const run = () => {
      step(simulationRef.current, linkIndexes, height, alpha)
      alpha *= 0.976
      setTick((value) => value + 1)
      if (alpha > 0.02) {
        frameRef.current = requestAnimationFrame(run)
      } else {
        frameRef.current = null
      }
    }
    frameRef.current = requestAnimationFrame(run)
    return () => {
      if (frameRef.current !== null) {
        cancelAnimationFrame(frameRef.current)
        frameRef.current = null
      }
    }
  }, [nodes, linkIndexes, degrees, height])

  const positions = simulationRef.current
  const positionById = new Map(positions.map((node) => [node.id, node]))
  const neighbours = useMemo(() => {
    if (!selectedId && !hovered) {
      return null
    }
    const focus = hovered ?? selectedId
    const set = new Set<string>([focus as string])
    for (const edge of edges) {
      if (edge.source === focus) {
        set.add(edge.target)
      }
      if (edge.target === focus) {
        set.add(edge.source)
      }
    }
    return set
  }, [edges, selectedId, hovered])

  if (positions.length === 0) {
    return (
      <div
        className="flex items-center justify-center rounded-takt border border-dashed border-[var(--line)] text-[12px] text-[var(--fg-3)]"
        style={{ height }}
      >
        В кейсе нет связей для построения графа
      </div>
    )
  }

  return (
    <svg
      viewBox={`0 0 ${WIDTH} ${height}`}
      className="w-full select-none"
      style={{ height }}
      role="img"
      aria-label="Граф связей расследования"
    >
      <defs>
        <radialGradient id="graph-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#2dd4bf" stopOpacity="0.28" />
          <stop offset="100%" stopColor="#2dd4bf" stopOpacity="0" />
        </radialGradient>
      </defs>

      {edges.map((edge, index) => {
        const from = positionById.get(edge.source)
        const to = positionById.get(edge.target)
        if (!from || !to) {
          return null
        }
        const played = activeEventIds.has(edge.event_id)
        const dimmed = neighbours ? !(neighbours.has(edge.source) && neighbours.has(edge.target)) : false
        return (
          <line
            key={`${edge.source}|${edge.target}|${edge.type}|${index}`}
            x1={from.x}
            y1={from.y}
            x2={to.x}
            y2={to.y}
            stroke={played ? 'var(--teal-1)' : 'var(--line-strong)'}
            strokeWidth={played ? 1.6 : 1}
            strokeOpacity={dimmed ? 0.15 : played ? 0.85 : 0.4}
            strokeDasharray={played ? '5 7' : undefined}
            className={played ? 'investigation-edge-flow' : undefined}
          >
            <title>{`${edge.source} → ${edge.target} (${edge.type})`}</title>
          </line>
        )
      })}

      {positions.map((node, index) => {
        const radius = nodeRadius(node)
        const isSelected = node.id === selectedId
        const dimmed = neighbours ? !neighbours.has(node.id) : false
        return (
          // Позиция задаётся SVG-атрибутом на внешней группе, а масштабирующая
          // анимация — CSS на внутренней: CSS-свойство transform перебивает
          // одноимённый атрибут, и совмещение их на одном элементе роняет раскладку.
          <g key={node.id} transform={`translate(${node.x} ${node.y})`} opacity={dimmed ? 0.28 : 1}>
            <g
              className="investigation-node cursor-pointer"
              style={{ animationDelay: `${Math.min(index * 26, 520)}ms` }}
              onClick={() => onSelect(isSelected ? null : { id: node.id, type: node.type, value: node.value })}
              onMouseEnter={() => setHovered(node.id)}
              onMouseLeave={() => setHovered(null)}
              tabIndex={0}
              role="button"
              aria-label={`${NODE_KIND_LABELS[node.type] ?? node.type}: ${node.value}`}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault()
                  onSelect(isSelected ? null : { id: node.id, type: node.type, value: node.value })
                }
              }}
            >
              {isSelected ? <circle r={radius + 16} fill="url(#graph-glow)" className="investigation-pulse" /> : null}
              <circle
                r={radius}
                fill={nodeColor(node.type)}
                fillOpacity={isSelected ? 0.95 : 0.72}
                stroke={isSelected ? 'var(--fg-1)' : 'var(--bg-0)'}
                strokeWidth={isSelected ? 2 : 1.5}
              />
              <text
                y={radius + 13}
                textAnchor="middle"
                className="pointer-events-none fill-[var(--fg-2)] text-[10px]"
              >
                {node.value.length > 22 ? `${node.value.slice(0, 20)}…` : node.value}
              </text>
            </g>
          </g>
        )
      })}
    </svg>
  )
}
