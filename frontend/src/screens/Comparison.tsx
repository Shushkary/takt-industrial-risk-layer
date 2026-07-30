import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { motion, useReducedMotion } from 'framer-motion';
import {
  fetchAttackChain,
  fetchBenchmark,
  fetchCaseById,
  fetchEntityBaseline,
  fetchRawEvents,
} from '../api/client';
import { theme } from '../styles/theme';

const CHAIN_CASE_ID = 'CASE-2026-0731';
const ATTACK_TECHNIQUES = [
  { id: 'T0840', label: 'Network Connection Enumeration' },
  { id: 'T0859', label: 'Valid Accounts' },
  { id: 'T0831', label: 'Manipulation of Control' },
];

function useStopwatch() {
  const [ms, setMs] = useState(0);
  const [running, setRunning] = useState(false);
  const start = useRef(0);
  const frame = useRef(0);

  useEffect(() => {
    if (!running) return;
    start.current = performance.now() - ms;
    const tick = () => {
      setMs(performance.now() - start.current);
      frame.current = requestAnimationFrame(tick);
    };
    frame.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame.current);
    // The elapsed value is intentionally captured when the timer starts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  return {
    ms,
    running,
    start: () => setRunning(true),
    stop: () => setRunning(false),
    reset: () => {
      setRunning(false);
      setMs(0);
    },
  };
}

function formatStopwatch(ms: number) {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const centiseconds = Math.floor((ms % 1000) / 10);
  return `${String(minutes).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}.${String(centiseconds).padStart(2, '0')}`;
}

export function Comparison() {
  const reduceMotion = useReducedMotion();
  const { data: raw } = useQuery({ queryKey: ['raw'], queryFn: fetchRawEvents });
  const { data: benchmark } = useQuery({ queryKey: ['bench'], queryFn: fetchBenchmark });
  const { data: incident } = useQuery({
    queryKey: ['case', CHAIN_CASE_ID],
    queryFn: () => fetchCaseById(CHAIN_CASE_ID),
  });
  const { data: chain } = useQuery({
    queryKey: ['chain', CHAIN_CASE_ID],
    queryFn: () => fetchAttackChain(CHAIN_CASE_ID),
  });
  const { data: baseline } = useQuery({
    queryKey: ['baseline', 'host', 'plc-rtu-14'],
    queryFn: () => fetchEntityBaseline('host', 'plc-rtu-14'),
  });

  const manual = useStopwatch();
  const takt = useStopwatch();
  const [found, setFound] = useState<Set<number>>(new Set());
  const [confirmed, setConfirmed] = useState(false);
  const attackSteps = raw?.attack_step_count ?? 6;

  useEffect(() => {
    if (found.size >= attackSteps && manual.running) manual.stop();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [found, attackSteps]);

  const bar = useMemo(() => {
    if (!benchmark) return null;
    return {
      manual: 100,
      takt: Math.max(5, (benchmark.result.takt_total_sec / benchmark.result.manual_total_sec) * 100),
    };
  }, [benchmark]);

  return (
    <main className="app-frame">
      <AppChrome />

      <header className="page-hero">
        <div>
          <div className="eyebrow">Operator efficiency benchmark</div>
          <h1 className="page-title">От сигнала к решению</h1>
          <p className="page-lede">
            Один IEC-104 инцидент, два сценария triage. Сравните сырой поток SIEM
            с контекстом, который ТАКТ собирает в доказуемую цепочку.
          </p>
          <div className="standards-row" aria-label="Используемые стандарты">
            <span className="standard-pill"><strong>MITRE</strong> ATT&amp;CK for ICS</span>
            <span className="standard-pill"><strong>IEC</strong> 60870-5-104</span>
            <span className="standard-pill"><strong>WCAG</strong> 2.2 AA</span>
          </div>
        </div>
        <Link className="secondary-link" to="/">
          <span aria-hidden="true">←</span> Вернуться в очередь
        </Link>
      </header>

      {benchmark && (
        <section className="metric-shell" aria-label="Итоговая метрика">
          <div className="metric-grid">
            <Metric label="Ручной triage" value={benchmark.result.manual_human} color={theme.colors.critical} note="Сырой поток SIEM" />
            <Metric label="Режим ТАКТ" value={benchmark.result.takt_human} color={theme.colors.success} note="Коррелированный кейс" />
            <Metric label="Экономия" value={benchmark.result.seconds_saved_human} color={theme.colors.accent} note="На один инцидент" />
            <Metric label="Ускорение" value={`×${benchmark.result.speedup_x}`} color={theme.colors.medium} note="По модели стенда" />
          </div>

          {bar && (
            <div className="comparison-bars" aria-label="Сравнение длительности">
              <BarRow label="Вручную" width={bar.manual} value={benchmark.result.manual_human} color={theme.colors.critical} />
              <BarRow label="ТАКТ" width={bar.takt} value={benchmark.result.takt_human} color={theme.colors.success} />
            </div>
          )}

          <p className="model-note">
            Параметрическая модель: {benchmark.dataset.raw_events_total} событий,
            из них {benchmark.dataset.attack_events} относятся к атаке; источников — {benchmark.dataset.sources}.
            Интерактивные таймеры ниже измеряют фактическое время оператора на том же наборе.
          </p>
        </section>
      )}

      <section className="mode-grid" aria-label="Сравнение рабочих режимов">
        <ModePanel
          kicker="Без корреляции"
          title="Полностью ручной режим"
          color={theme.colors.critical}
          badge={`${found.size} / ${attackSteps} найдено`}
        >
          <p className="panel-description">
            Найдите шесть связанных событий среди шума. Уровень важности обозначен
            текстом и цветом; каждое событие доступно с клавиатуры.
          </p>
          <Stopwatch
            stopwatch={manual}
            done={found.size >= attackSteps}
            onStart={() => {
              setFound(new Set());
              manual.reset();
              manual.start();
            }}
          />

          <div className="event-console" aria-label="Сырой поток событий">
            {(raw?.items ?? []).map((event) => {
              const foundEvent = event.attack_step != null && found.has(event.attack_step);
              const actionable = manual.running && event.is_attack;
              const eventColor = event.level === 'ALERT'
                ? theme.colors.critical
                : event.level === 'NOTICE'
                  ? theme.colors.medium
                  : theme.colors.textMuted;

              return (
                <button
                  className={`event-row${foundEvent ? ' is-found' : ''}`}
                  key={event.id}
                  type="button"
                  disabled={!actionable}
                  onClick={() => {
                    if (event.attack_step != null) {
                      setFound((current) => new Set(current).add(event.attack_step!));
                    }
                  }}
                  style={{ '--event-color': eventColor } as React.CSSProperties}
                  aria-label={`${event.ts.slice(11, 19)}, ${event.source_class}, ${event.level}, ${event.message}`}
                >
                  <span className="event-time">{event.ts.slice(11, 19)}</span>
                  <span className="event-source">{event.source_class}</span>
                  <span className="event-level">{event.level}</span>
                  <span className="event-message">{foundEvent ? '✓ ' : ''}{event.message}</span>
                </button>
              );
            })}
          </div>
          {benchmark && <Breakdown data={benchmark.manual.breakdown} color={theme.colors.critical} />}
        </ModePanel>

        <ModePanel
          kicker="Context-assisted"
          title="Режим ТАКТ"
          color={theme.colors.success}
          badge={confirmed ? 'Подтверждено' : 'Готов к triage'}
        >
          <p className="panel-description">
            Коррелированный кейс объединяет объяснение, технику ATT&amp;CK,
            причинную цепочку и отклонение от baseline.
          </p>
          <Stopwatch
            stopwatch={takt}
            done={confirmed}
            onStart={() => {
              setConfirmed(false);
              takt.reset();
              takt.start();
            }}
          />

          <div className="case-console">
            {incident && (
              <>
                <div className="case-identity">
                  <span
                    className="severity-pill"
                    style={{ '--severity-color': theme.colors.critical } as React.CSSProperties}
                  >
                    Critical
                  </span>
                  <span className="incident-id">{incident.id}</span>
                </div>
                <h2 className="case-title">{incident.title}</h2>
                <div className="xai-callout">
                  <strong>XAI · почему это инцидент</strong><br />
                  {incident.xai_summary}
                </div>
              </>
            )}

            <div className="section-label">MITRE ATT&amp;CK for ICS · техники</div>
            <div className="standards-row">
              {ATTACK_TECHNIQUES.map((technique) => (
                <span className="technique-pill" key={technique.id} title={technique.label}>
                  <strong>{technique.id}</strong> {technique.label}
                </span>
              ))}
            </div>

            {chain && chain.edges.length > 0 && (
              <>
                <div className="section-label">Доказуемая цепочка корреляции</div>
                <div className="attack-chain">
                  {chain.edges.map((edge, index) => (
                    <motion.div
                      className="attack-step"
                      data-step={index + 1}
                      key={edge.id}
                      initial={reduceMotion ? false : { opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: reduceMotion ? 0 : index * 0.04 }}
                    >
                      <strong>{edge.source.split(':')[1]} → {edge.target.split(':')[1]}</strong>
                      <span>{edge.correlation_reason}</span>
                    </motion.div>
                  ))}
                </div>
              </>
            )}

            {baseline && (
              <>
                <div className="section-label">Behavior baseline · plc-rtu-14 · z-score</div>
                <Sparkline values={baseline.z_scores} color={theme.colors.medium} />
              </>
            )}
          </div>

          <button
            className="confirm-button"
            type="button"
            disabled={!takt.running || confirmed}
            onClick={() => {
              setConfirmed(true);
              takt.stop();
            }}
          >
            {confirmed ? 'Инцидент подтверждён ✓' : 'Подтвердить инцидент'}
          </button>
          {benchmark && <Breakdown data={benchmark.takt.breakdown} color={theme.colors.success} />}
        </ModePanel>
      </section>
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

function Metric({
  label,
  value,
  note,
  color,
}: {
  label: string;
  value: string;
  note: string;
  color: string;
}) {
  return (
    <div className="metric-card" style={{ '--metric-color': color } as React.CSSProperties}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-note">{note}</div>
    </div>
  );
}

function BarRow({
  label,
  width,
  value,
  color,
}: {
  label: string;
  width: number;
  value: string;
  color: string;
}) {
  return (
    <div className="comparison-bar-row">
      <span className="comparison-bar-label">{label}</span>
      <div className="comparison-bar-track">
        <motion.div
          className="comparison-bar-fill"
          initial={{ width: 0 }}
          animate={{ width: `${width}%` }}
          transition={{ duration: 0.45 }}
          style={{ '--bar-color': color } as React.CSSProperties}
        />
      </div>
      <span className="comparison-bar-value">{value}</span>
    </div>
  );
}

function ModePanel({
  kicker,
  title,
  color,
  badge,
  children,
}: {
  kicker: string;
  title: string;
  color: string;
  badge: string;
  children: React.ReactNode;
}) {
  return (
    <article className="mode-panel" style={{ '--panel-color': color } as React.CSSProperties}>
      <div className="panel-heading">
        <div>
          <div className="panel-kicker">{kicker}</div>
          <h2 className="panel-title">{title}</h2>
        </div>
        <span className="progress-badge">{badge}</span>
      </div>
      {children}
    </article>
  );
}

function Stopwatch({
  stopwatch,
  onStart,
  done,
}: {
  stopwatch: ReturnType<typeof useStopwatch>;
  onStart: () => void;
  done: boolean;
}) {
  return (
    <div className="stopwatch-row">
      <div className={`stopwatch-value${done ? ' is-done' : ''}`} aria-live="off">
        {formatStopwatch(stopwatch.ms)}
      </div>
      <button
        className="action-button primary"
        type="button"
        onClick={onStart}
        disabled={stopwatch.running}
      >
        {stopwatch.running ? 'Разбор идёт…' : 'Начать разбор'}
      </button>
      {done && <span className="status-pill" style={{ '--status-color': theme.colors.success } as React.CSSProperties}>Готово</span>}
    </div>
  );
}

function Breakdown({ data, color }: { data: Record<string, number>; color: string }) {
  return (
    <div className="breakdown-list" aria-label="Этапы модели времени">
      {Object.entries(data).map(([label, seconds]) => (
        <div
          className="breakdown-row"
          key={label}
          style={{ '--breakdown-color': color } as React.CSSProperties}
        >
          <span>{label}</span>
          <span>{seconds} с</span>
        </div>
      ))}
    </div>
  );
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const width = 520;
  const height = 82;
  const padding = 8;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const points = values.map((value, index) => {
    const x = padding + (index / (values.length - 1)) * (width - padding * 2);
    const y = height - padding - ((value - min) / range) * (height - padding * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');

  return (
    <svg
      className="baseline-chart"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="График отклонения поведения PLC от baseline"
      preserveAspectRatio="none"
    >
      <line x1={0} x2={width} y1={height / 2} y2={height / 2} stroke="#38383a" strokeDasharray="4 5" />
      <polyline points={points} fill="none" stroke={color} strokeWidth={2} vectorEffect="non-scaling-stroke" />
      {values.map((value, index) => {
        const x = padding + (index / (values.length - 1)) * (width - padding * 2);
        const y = height - padding - ((value - min) / range) * (height - padding * 2);
        const anomaly = value >= 3;
        return (
          <circle
            key={`${index}-${value}`}
            cx={x}
            cy={y}
            r={anomaly ? 4 : 2}
            fill={anomaly ? theme.colors.critical : color}
          />
        );
      })}
    </svg>
  );
}
