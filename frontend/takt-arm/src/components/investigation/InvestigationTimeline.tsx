import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Pause, Play, RotateCcw } from 'lucide-react'
import type { InvestigationEvent } from '../../investigation/types'
import { SOURCE_COLORS, SOURCE_LABELS, operationLabel } from '../../investigation/types'

/**
 * Таймлайн расследования (ТЗ п. 5.4) с воспроизведением хронологии.
 *
 * Аналитик видит не «список событий», а порядок развития инцидента: курсор идёт
 * по времени, события зажигаются по мере наступления, граф связей подсвечивает
 * только те рёбра, которые к этому моменту уже наблюдались.
 */

type Props = {
  events: InvestigationEvent[]
  /** Момент курсора в миллисекундах эпохи. */
  cursor: number
  onCursorChange: (value: number) => void
  selectedEventId: string | null
  onSelectEvent: (eventId: string | null) => void
}

const PLAYBACK_SECONDS = 9

function timeOf(event: InvestigationEvent): number {
  const value = Date.parse(event.observed_at)
  return Number.isNaN(value) ? 0 : value
}

function formatClock(value: number): string {
  if (!Number.isFinite(value)) {
    return '—'
  }
  return new Date(value).toISOString().slice(11, 19)
}

export function InvestigationTimeline({ events, cursor, onCursorChange, selectedEventId, onSelectEvent }: Props) {
  const [playing, setPlaying] = useState(false)
  const frameRef = useRef<number | null>(null)

  const ordered = useMemo(() => [...events].sort((a, b) => timeOf(a) - timeOf(b)), [events])
  const start = ordered.length > 0 ? timeOf(ordered[0]) : 0
  const end = ordered.length > 0 ? timeOf(ordered[ordered.length - 1]) : 0
  const span = Math.max(end - start, 1)

  const ratio = Math.min(1, Math.max(0, (cursor - start) / span))

  const stop = useCallback(() => {
    setPlaying(false)
    if (frameRef.current !== null) {
      cancelAnimationFrame(frameRef.current)
      frameRef.current = null
    }
  }, [])

  useEffect(() => {
    if (!playing || ordered.length === 0) {
      return
    }
    const from = cursor >= end ? start : cursor
    const startedAt = performance.now()
    const remaining = ((end - from) / span) * PLAYBACK_SECONDS * 1000

    const run = (now: number) => {
      const progress = Math.min(1, (now - startedAt) / Math.max(remaining, 1))
      onCursorChange(from + (end - from) * progress)
      if (progress >= 1) {
        setPlaying(false)
        frameRef.current = null
        return
      }
      frameRef.current = requestAnimationFrame(run)
    }
    frameRef.current = requestAnimationFrame(run)
    return () => {
      if (frameRef.current !== null) {
        cancelAnimationFrame(frameRef.current)
        frameRef.current = null
      }
    }
    // cursor намеренно не в зависимостях: иначе каждый кадр перезапускал бы проигрывание
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [playing, ordered.length, start, end, span, onCursorChange])

  useEffect(() => stop, [stop])

  if (ordered.length === 0) {
    return <div className="text-[12px] text-[var(--fg-3)]">В кейсе нет событий для таймлайна</div>
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <button
          type="button"
          className="takt-focus-ring flex items-center gap-1.5 rounded-takt border border-[var(--line-strong)] bg-[var(--bg-2)] px-2.5 py-1.5 text-[12px] text-[var(--fg-1)] transition-colors duration-takt hover:border-[var(--teal-2)]"
          onClick={() => (playing ? stop() : setPlaying(true))}
          aria-label={playing ? 'Остановить воспроизведение' : 'Воспроизвести хронологию'}
        >
          {playing ? <Pause size={13} /> : <Play size={13} />}
          {playing ? 'Пауза' : 'Проиграть'}
        </button>
        <button
          type="button"
          className="takt-focus-ring flex items-center gap-1.5 rounded-takt border border-[var(--line)] px-2.5 py-1.5 text-[12px] text-[var(--fg-2)] transition-colors duration-takt hover:text-[var(--fg-1)]"
          onClick={() => {
            stop()
            onCursorChange(end)
          }}
          aria-label="Показать всю цепочку"
        >
          <RotateCcw size={13} />
          Вся цепочка
        </button>
        <div className="ml-auto font-mono text-[12px] text-[var(--fg-2)]">
          {formatClock(cursor)} <span className="text-[var(--fg-3)]">из</span> {formatClock(end)}
        </div>
      </div>

      <input
        type="range"
        min={start}
        max={end}
        step={Math.max(1, Math.round(span / 500))}
        value={Math.round(cursor)}
        onChange={(event) => {
          stop()
          onCursorChange(Number(event.target.value))
        }}
        className="investigation-scrub takt-focus-ring w-full"
        aria-label="Позиция на таймлайне расследования"
      />

      <div className="relative mt-1 h-[86px] rounded-takt border border-[var(--line)] bg-[var(--bg-2)] px-3">
        <div className="absolute inset-x-3 top-[38px] h-px bg-[var(--line-strong)]" />
        <div
          className="absolute inset-y-2 w-px bg-[var(--teal-1)] transition-[left] duration-100 ease-linear"
          style={{ left: `calc(0.75rem + ${ratio} * (100% - 1.5rem))` }}
        >
          <div className="absolute -left-[3px] top-0 h-[7px] w-[7px] rounded-full bg-[var(--teal-1)]" />
        </div>

        {ordered.map((event) => {
          const position = (timeOf(event) - start) / span
          const played = timeOf(event) <= cursor
          const isSelected = event.event_id === selectedEventId
          const color = SOURCE_COLORS[event.source] ?? 'var(--fg-3)'
          return (
            <button
              key={event.event_id}
              type="button"
              className="takt-focus-ring absolute top-[26px] -ml-[9px] flex h-[24px] w-[18px] items-center justify-center"
              style={{ left: `calc(0.75rem + ${position} * (100% - 1.5rem))` }}
              onClick={() => onSelectEvent(isSelected ? null : event.event_id)}
              title={`${SOURCE_LABELS[event.source] ?? event.source}: ${operationLabel(event.operation)} (${event.operation})`}
              aria-label={`Событие ${operationLabel(event.operation)}, источник ${SOURCE_LABELS[event.source] ?? event.source}`}
            >
              <span
                className={`block rounded-full transition-all duration-takt-slow ease-takt ${
                  played ? 'investigation-dot-live' : ''
                }`}
                style={{
                  width: isSelected ? 13 : played ? 10 : 7,
                  height: isSelected ? 13 : played ? 10 : 7,
                  backgroundColor: played ? color : 'var(--line-strong)',
                  boxShadow: isSelected ? `0 0 0 3px color-mix(in srgb, ${color} 35%, transparent)` : undefined,
                }}
              />
            </button>
          )
        })}

        <div className="absolute inset-x-3 bottom-2 flex justify-between font-mono text-[10px] text-[var(--fg-3)]">
          <span>{formatClock(start)}</span>
          <span>{formatClock(end)}</span>
        </div>
      </div>
    </div>
  )
}
