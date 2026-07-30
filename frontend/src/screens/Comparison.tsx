// Экран «Сравнение»: полностью ручной режим vs режим ТАКТ.
// Метрика проекта — время обработки данных оператором.

import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  fetchRawEvents,
  fetchBenchmark,
  fetchCaseById,
  fetchAttackChain,
  fetchEntityBaseline,
} from '../api/client';
import { theme } from '../styles/theme';

const CHAIN_CASE_ID = 'CASE-2026-0731';

function useStopwatch() {
  const [ms, setMs] = useState(0);
  const [running, setRunning] = useState(false);
  const start = useRef<number>(0);
  const raf = useRef<number>(0);
  useEffect(() => {
    if (!running) return;
    start.current = performance.now() - ms;
    const tick = () => {
      setMs(performance.now() - start.current);
      raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);
  return {
    ms,
    running,
    startSw: () => setRunning(true),
    stopSw: () => setRunning(false),
    reset: () => { setRunning(false); setMs(0); },
  };
}

function fmt(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const cs = Math.floor((ms % 1000) / 10);
  return `${String(m).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}.${String(cs).padStart(2, '0')}`;
}

export function Comparison() {
  const { data: raw } = useQuery({ queryKey: ['raw'], queryFn: fetchRawEvents });
  const { data: bench } = useQuery({ queryKey: ['bench'], queryFn: fetchBenchmark });
  const { data: chainCase } = useQuery({ queryKey: ['case', CHAIN_CASE_ID], queryFn: () => fetchCaseById(CHAIN_CASE_ID) });
  const { data: chain } = useQuery({ queryKey: ['chain', CHAIN_CASE_ID], queryFn: () => fetchAttackChain(CHAIN_CASE_ID) });
  const { data: baseline } = useQuery({ queryKey: ['bl', 'host', 'plc-rtu-14'], queryFn: () => fetchEntityBaseline('host', 'plc-rtu-14') });

  // Ручной режим: оператор должен найти все ALERT-события среди шума.
  const manual = useStopwatch();
  const [found, setFound] = useState<Set<number>>(new Set());
  const attackSteps = raw?.attack_step_count ?? 6;

  useEffect(() => {
    if (found.size >= attackSteps && manual.running) manual.stopSw();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [found, attackSteps]);

  // Режим ТАКТ.
  const takt = useStopwatch();
  const [confirmed, setConfirmed] = useState(false);

  const c = theme.colors;

  const bar = useMemo(() => {
    if (!bench) return null;
    const max = bench.result.manual_total_sec;
    return {
      manualPct: 100,
      taktPct: Math.max(4, (bench.result.takt_total_sec / max) * 100),
    };
  }, [bench]);

  return (
    <div style={{ minHeight: '100vh', background: c.background, color: c.textPrimary, padding: theme.spacing.lg }}>
      {/* Шапка */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: theme.spacing.lg }}>
        <div>
          <h1 style={{ fontSize: 24 }}>Сравнение режимов обработки инцидента</h1>
          <div style={{ color: c.textSecondary, marginTop: 4 }}>
            Метрика: <b style={{ color: c.accent }}>время обработки данных оператором</b>. Один и тот же инцидент — цепочка IEC-104.
          </div>
        </div>
        <Link to="/" style={{ color: c.accent, textDecoration: 'none', border: `1px solid ${c.border}`, padding: '8px 14px', borderRadius: 8 }}>
          ← Очередь инцидентов
        </Link>
      </div>

      {/* Итоговая метрика (модель) */}
      {bench && (
        <div style={{ background: c.surface, border: `1px solid ${c.border}`, borderRadius: 12, padding: theme.spacing.lg, marginBottom: theme.spacing.lg }}>
          <div style={{ display: 'flex', gap: theme.spacing.xl, flexWrap: 'wrap', marginBottom: theme.spacing.md }}>
            <Metric label="🖐️ Ручной режим" value={bench.result.manual_human} color={c.critical} />
            <Metric label="⚡ Режим ТАКТ" value={bench.result.takt_human} color={c.success} />
            <Metric label="Экономия" value={bench.result.seconds_saved_human} color={c.accent} />
            <Metric label="Ускорение" value={`×${bench.result.speedup_x}`} color={c.medium} />
          </div>
          {bar && (
            <div style={{ display: 'grid', gap: 8 }}>
              <BarRow label="Ручной" pct={bar.manualPct} color={c.critical} text={bench.result.manual_human} />
              <BarRow label="ТАКТ" pct={bar.taktPct} color={c.success} text={bench.result.takt_human} />
            </div>
          )}
          <div style={{ color: c.textMuted, fontSize: 12, marginTop: 8 }}>
            Оценка параметрической модели ({bench.dataset.raw_events_total} событий в потоке,
            {' '}{bench.dataset.attack_events} — реальная атака, {bench.dataset.sources} источника).
            Ниже — интерактивный секундомер, чтобы измерить фактическое время на тех же данных стенда.
          </div>
        </div>
      )}

      {/* Две панели */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: theme.spacing.lg }}>
        {/* ЛЕВАЯ: РУЧНОЙ РЕЖИМ */}
        <Panel title="Полностью ручной режим" accent={c.critical}>
          <p style={{ color: c.textSecondary, fontSize: 13, marginBottom: 8 }}>
            Сырой нескоррелированный поток из SIEM. Найдите все события атаки (уровень <b style={{ color: c.critical }}>ALERT/NOTICE</b>)
            среди шума — как это делается вручную. Найдено: <b>{found.size}</b> / {attackSteps}.
          </p>
          <StopwatchBar sw={manual} onStart={() => { setFound(new Set()); manual.reset(); manual.startSw(); }} done={found.size >= attackSteps} />
          <div style={{ height: 420, overflowY: 'auto', background: '#141414', border: `1px solid ${c.border}`, borderRadius: 8, padding: 8, fontFamily: 'monospace', fontSize: 12 }}>
            {(raw?.items ?? []).map((e) => {
              const isFound = e.attack_step != null && found.has(e.attack_step);
              const clickable = manual.running && e.is_attack;
              return (
                <div
                  key={e.id}
                  onClick={() => {
                    if (clickable && e.attack_step != null) setFound((s) => new Set(s).add(e.attack_step!));
                  }}
                  style={{
                    padding: '2px 6px',
                    marginBottom: 1,
                    borderRadius: 3,
                    cursor: clickable ? 'pointer' : 'default',
                    color: e.level === 'ALERT' ? c.critical : e.level === 'NOTICE' ? c.medium : c.textMuted,
                    background: isFound ? 'rgba(68,255,136,0.15)' : 'transparent',
                    outline: isFound ? `1px solid ${c.success}` : 'none',
                  }}
                >
                  <span style={{ color: c.textMuted }}>{e.ts.slice(11, 19)}</span>{' '}
                  <span style={{ color: c.accent }}>{e.source_class.padEnd(8)}</span>{' '}
                  [{e.level}] {e.message}
                </div>
              );
            })}
          </div>
          {bench && <Breakdown data={bench.manual.breakdown} color={c.critical} />}
        </Panel>

        {/* ПРАВАЯ: РЕЖИМ ТАКТ */}
        <Panel title="Режим ТАКТ" accent={c.success}>
          <p style={{ color: c.textSecondary, fontSize: 13, marginBottom: 8 }}>
            Готовый коррелированный кейс: XAI-резюме, граф атаки и baseline сущности. Проверьте и подтвердите.
          </p>
          <StopwatchBar sw={takt} onStart={() => { setConfirmed(false); takt.reset(); takt.startSw(); }} done={confirmed} />
          <div style={{ height: 420, overflowY: 'auto', background: '#141414', border: `1px solid ${c.border}`, borderRadius: 8, padding: 12 }}>
            {chainCase && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ color: c.critical, fontWeight: 700 }}>{chainCase.id} · {chainCase.severity.toUpperCase()}</div>
                <div style={{ fontWeight: 600, marginTop: 2 }}>{(chainCase as any).title}</div>
                <div style={{ color: c.textSecondary, fontSize: 13, marginTop: 6, lineHeight: 1.5 }}>
                  <b style={{ color: c.accent }}>XAI:</b> {(chainCase as any).xai_summary}
                </div>
              </div>
            )}
            {chain && chain.edges.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ color: c.textMuted, fontSize: 12, marginBottom: 4 }}>ЦЕПОЧКА АТАКИ (корреляция автоматом)</div>
                {chain.edges.map((ed, i) => (
                  <motion.div key={ed.id} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}
                    style={{ fontSize: 12, padding: '4px 8px', borderLeft: `2px solid ${c.accent}`, marginBottom: 4, background: c.surface, borderRadius: 4 }}>
                    <b>{ed.source.split(':')[1]}</b> → <b>{ed.target.split(':')[1]}</b>
                    <div style={{ color: c.textSecondary }}>{ed.correlation_reason}</div>
                  </motion.div>
                ))}
              </div>
            )}
            {baseline && (
              <div>
                <div style={{ color: c.textMuted, fontSize: 12, marginBottom: 4 }}>BASELINE plc-rtu-14 (z-score, Welford)</div>
                <Sparkline values={baseline.z_scores} color={c.medium} />
              </div>
            )}
          </div>
          <button
            disabled={!takt.running || confirmed}
            onClick={() => { setConfirmed(true); takt.stopSw(); }}
            style={{
              marginTop: 10, width: '100%', padding: '10px', borderRadius: 8, border: 'none',
              background: !takt.running || confirmed ? c.border : c.success,
              color: !takt.running || confirmed ? c.textMuted : '#0a0a0a',
              fontWeight: 700, cursor: !takt.running || confirmed ? 'default' : 'pointer',
            }}
          >
            {confirmed ? '✓ Инцидент подтверждён' : 'Подтвердить инцидент'}
          </button>
          {bench && <Breakdown data={bench.takt.breakdown} color={c.success} />}
        </Panel>
      </div>
    </div>
  );
}

function Metric({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div>
      <div style={{ color: theme.colors.textSecondary, fontSize: 13 }}>{label}</div>
      <div style={{ color, fontSize: 28, fontWeight: 800 }}>{value}</div>
    </div>
  );
}

function BarRow({ label, pct, color, text }: { label: string; pct: number; color: string; text: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 60, color: theme.colors.textSecondary, fontSize: 13 }}>{label}</div>
      <div style={{ flex: 1, background: '#141414', borderRadius: 4, overflow: 'hidden', height: 22 }}>
        <motion.div initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ duration: 0.4 }}
          style={{ height: '100%', background: color, display: 'flex', alignItems: 'center', paddingLeft: 8, color: '#0a0a0a', fontSize: 12, fontWeight: 700 }}>
          {text}
        </motion.div>
      </div>
    </div>
  );
}

function Panel({ title, accent, children }: { title: string; accent: string; children: React.ReactNode }) {
  return (
    <div style={{ background: theme.colors.surface, border: `1px solid ${theme.colors.border}`, borderRadius: 12, padding: theme.spacing.md }}>
      <h2 style={{ fontSize: 18, borderLeft: `4px solid ${accent}`, paddingLeft: 10, marginBottom: 10 }}>{title}</h2>
      {children}
    </div>
  );
}

function StopwatchBar({ sw, onStart, done }: { sw: ReturnType<typeof useStopwatch>; onStart: () => void; done: boolean }) {
  const c = theme.colors;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
      <div style={{ fontFamily: 'monospace', fontSize: 22, fontWeight: 700, color: done ? c.success : c.textPrimary }}>{fmt(sw.ms)}</div>
      <button onClick={onStart} disabled={sw.running}
        style={{ padding: '6px 12px', borderRadius: 6, border: 'none', background: sw.running ? c.border : c.accent, color: '#fff', cursor: sw.running ? 'default' : 'pointer', fontWeight: 600 }}>
        {sw.running ? 'Идёт разбор…' : 'Начать разбор'}
      </button>
      {done && <span style={{ color: c.success, fontWeight: 700 }}>Готово ✓</span>}
    </div>
  );
}

function Breakdown({ data, color }: { data: Record<string, number>; color: string }) {
  return (
    <div style={{ marginTop: 10, fontSize: 12 }}>
      <div style={{ color: theme.colors.textMuted, marginBottom: 4 }}>Модель времени (сек):</div>
      {Object.entries(data).map(([k, v]) => (
        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', color: theme.colors.textSecondary, padding: '1px 0' }}>
          <span>{k}</span><span style={{ color }}>{v}</span>
        </div>
      ))}
    </div>
  );
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const w = 320, h = 60, pad = 4;
  const min = Math.min(...values), max = Math.max(...values);
  const range = max - min || 1;
  const pts = values.map((v, i) => {
    const x = pad + (i / (values.length - 1)) * (w - 2 * pad);
    const y = h - pad - ((v - min) / range) * (h - 2 * pad);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return (
    <svg width={w} height={h} style={{ background: '#0f0f0f', borderRadius: 4 }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} />
      {values.map((v, i) => {
        const x = pad + (i / (values.length - 1)) * (w - 2 * pad);
        const y = h - pad - ((v - min) / range) * (h - 2 * pad);
        const hot = v >= 3;
        return <circle key={i} cx={x} cy={y} r={hot ? 3 : 1.5} fill={hot ? theme.colors.critical : color} />;
      })}
    </svg>
  );
}
