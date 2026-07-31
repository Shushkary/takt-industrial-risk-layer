import { useEffect, useMemo, useRef, useState } from 'react'
import { SOURCE_COLORS, SOURCE_HINTS, SOURCE_LABELS, riskClassLabel } from '../../investigation/types'

/**
 * Схема слияния источников (ТЗ п. 4.1, п. 12.1): четыре класса ИБ-продуктов
 * сходятся в один кейс. По кривым идут частицы — их плотность пропорциональна
 * числу событий класса в кейсе, поэтому картинка показывает реальный вклад
 * источника, а не декоративный поток.
 */

type Props = {
  countsBySource: Record<string, number>
  caseTitle: string
  riskClass: string
  onSelectSource?: (source: string | null) => void
  activeSource?: string | null
}

const ORDER = ['edr', 'siem', 'ndr', 'ot'] as const
const WIDTH = 720
const HEIGHT = 150
const PARTICLES_PER_SOURCE = 5

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false
  }
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

function pointOn(from: { x: number; y: number }, to: { x: number; y: number }, control: { x: number; y: number }, t: number) {
  const inv = 1 - t
  return {
    x: inv * inv * from.x + 2 * inv * t * control.x + t * t * to.x,
    y: inv * inv * from.y + 2 * inv * t * control.y + t * t * to.y,
  }
}

export function SourceFusionRibbon({ countsBySource, caseTitle, riskClass, onSelectSource, activeSource }: Props) {
  const [phase, setPhase] = useState(0)
  const frameRef = useRef<number | null>(null)

  const lanes = useMemo(() => {
    const target = { x: WIDTH - 120, y: HEIGHT / 2 }
    return ORDER.map((source, index) => {
      const from = { x: 96, y: 26 + index * 32 }
      const control = { x: WIDTH * 0.58, y: from.y + (target.y - from.y) * 0.25 }
      return { source, from, to: target, control, count: countsBySource[source] ?? 0 }
    })
  }, [countsBySource])

  useEffect(() => {
    if (prefersReducedMotion()) {
      return
    }
    const run = () => {
      setPhase((value) => (value + 0.0055) % 1)
      frameRef.current = requestAnimationFrame(run)
    }
    frameRef.current = requestAnimationFrame(run)
    return () => {
      if (frameRef.current !== null) {
        cancelAnimationFrame(frameRef.current)
        frameRef.current = null
      }
    }
  }, [])

  const connected = lanes.filter((lane) => lane.count > 0).length

  return (
    <div className="takt-card p-3">
      <div className="mb-1 flex items-baseline justify-between gap-3">
        <div className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
          Единое окно расследования
        </div>
        <div className="text-[11px] text-[var(--fg-2)]">
          классов источников в кейсе: <span className="font-mono text-[var(--fg-1)]">{connected}</span> из 4
        </div>
      </div>

      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full" role="img" aria-label="Слияние источников в один кейс">
        <defs>
          <radialGradient id="fusion-core" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#2dd4bf" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#2dd4bf" stopOpacity="0" />
          </radialGradient>
        </defs>

        {lanes.map((lane) => {
          const color = SOURCE_COLORS[lane.source]
          const muted = lane.count === 0 || (activeSource != null && activeSource !== lane.source)
          const path = `M ${lane.from.x} ${lane.from.y} Q ${lane.control.x} ${lane.control.y} ${lane.to.x} ${lane.to.y}`
          return (
            <g key={lane.source} opacity={muted ? 0.3 : 1}>
              <path d={path} fill="none" stroke={color} strokeOpacity={0.32} strokeWidth={1.4} />
              {lane.count > 0
                ? Array.from({ length: PARTICLES_PER_SOURCE }, (_, index) => {
                    const t = (phase + index / PARTICLES_PER_SOURCE) % 1
                    const point = pointOn(lane.from, lane.to, lane.control, t)
                    return (
                      <circle
                        key={index}
                        cx={point.x}
                        cy={point.y}
                        r={2.2}
                        fill={color}
                        opacity={0.35 + 0.65 * (1 - Math.abs(t - 0.5) * 2) * 0.9}
                      />
                    )
                  })
                : null}
            </g>
          )
        })}

        {lanes.map((lane) => {
          const color = SOURCE_COLORS[lane.source]
          const muted = lane.count === 0
          return (
            <g
              key={`label-${lane.source}`}
              className="cursor-pointer"
              onClick={() => onSelectSource?.(activeSource === lane.source ? null : lane.source)}
              tabIndex={0}
              role="button"
              aria-label={`${SOURCE_LABELS[lane.source]}: ${lane.count} событий. ${SOURCE_HINTS[lane.source]}`}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault()
                  onSelectSource?.(activeSource === lane.source ? null : lane.source)
                }
              }}
            >
              <rect
                x={8}
                y={lane.from.y - 11}
                width={84}
                height={22}
                rx={3}
                fill="var(--bg-2)"
                stroke={activeSource === lane.source ? color : 'var(--line)'}
                strokeWidth={activeSource === lane.source ? 1.5 : 1}
                opacity={muted ? 0.45 : 1}
              />
              <circle cx={19} cy={lane.from.y} r={3.2} fill={color} opacity={muted ? 0.4 : 1} />
              <text x={28} y={lane.from.y + 3.5} className="fill-[var(--fg-1)] text-[10px]" opacity={muted ? 0.5 : 1}>
                {SOURCE_LABELS[lane.source]}
              </text>
              <text x={86} y={lane.from.y + 3.5} textAnchor="end" className="fill-[var(--fg-3)] text-[10px]">
                {lane.count}
              </text>
            </g>
          )
        })}

        <circle cx={WIDTH - 120} cy={HEIGHT / 2} r={38} fill="url(#fusion-core)" className="investigation-pulse" />
        <circle
          cx={WIDTH - 120}
          cy={HEIGHT / 2}
          r={19}
          fill="var(--bg-2)"
          stroke="var(--teal-1)"
          strokeWidth={1.5}
        />
        <text x={WIDTH - 120} y={HEIGHT / 2 + 4} textAnchor="middle" className="fill-[var(--fg-1)] text-[11px]">
          кейс
        </text>
        <text x={WIDTH - 74} y={HEIGHT / 2 - 6} className="fill-[var(--fg-2)] text-[10px]">
          {riskClassLabel(riskClass)}
        </text>
        <text x={WIDTH - 74} y={HEIGHT / 2 + 9} className="fill-[var(--fg-3)] text-[10px]">
          {caseTitle.length > 26 ? `${caseTitle.slice(0, 24)}…` : caseTitle}
        </text>
      </svg>
    </div>
  )
}
