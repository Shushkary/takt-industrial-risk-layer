// Верхняя командная строка SOC-консоли: бренд, часы UTC, состояние канала,
// бейдж обучения модели, индикатор хаоса, оператор смены.

import { useEffect, useState } from 'react';
import type { LinkState } from '../api/client';
import type { ChaosState } from '../types/api';

const CHAOS_LABEL: Record<ChaosState['mode'], string> = {
  off: 'НОРМА',
  burst: 'ВСПЛЕСК',
  drop_source: 'ОБРЫВ ИСТОЧНИКА',
  dup: 'ДУБЛИ',
  future: 'РАССИНХРОН ВРЕМЕНИ',
  malformed: 'БИТЫЙ PAYLOAD',
  latency: 'ЗАДЕРЖКА',
};

const LINK_META: Record<LinkState, { text: string; cls: string }> = {
  connecting: { text: 'CONNECTING', cls: 'is-warn' },
  live: { text: 'LIVE · SSE', cls: '' },
  stale: { text: 'STALE · нет данных', cls: 'is-warn' },
  polling: { text: 'POLL · резерв', cls: 'is-warn' },
  down: { text: 'OFFLINE', cls: 'is-down' },
};

interface CommandBarProps {
  /** Состояние канала данных. Если не передано — индикатор скрыт. */
  link?: LinkState;
  /** Показывать ли часы UTC (по умолчанию да). */
  showClock?: boolean;
  /** Имя оператора смены. */
  operator?: string;
  /** Возраст последних данных в секундах (для stale-подписи). */
  dataAgeSec?: number;
  /** Состояние инъекции хаоса. */
  chaos?: ChaosState;
  /** Открыть панель хаоса. */
  onToggleChaos?: () => void;
  /** Сводка обучения модели. */
  model?: { verdicts_total: number; calibration_delta: number };
}

function pad(value: number): string {
  return String(value).padStart(2, '0');
}

export function CommandBar({
  link,
  showClock = true,
  operator = 'operator.shift-A',
  dataAgeSec,
  chaos,
  onToggleChaos,
  model,
}: CommandBarProps) {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const utc = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())}`;
  const dateUtc = `${pad(now.getUTCDate())}.${pad(now.getUTCMonth() + 1)}.${now.getUTCFullYear()}`;
  const initials = operator.replace(/[^a-zа-я]/gi, '').slice(0, 2).toUpperCase() || 'OP';

  const linkMeta = link ? LINK_META[link] : null;
  const chaosActive = chaos && chaos.mode !== 'off';

  return (
    <header className="command-bar">
      <div className="brand-lockup">
        <div className="brand-mark" aria-hidden="true">T</div>
        <div>
          <div className="brand-name">TAKT · Industrial Risk Layer</div>
          <div className="brand-caption">SOC Operator Console</div>
        </div>
      </div>

      {showClock ? (
        <div className="command-clock" aria-label="Время UTC">
          <span className="clock-time">{utc}</span>
          <span className="clock-zone">UTC · {dateUtc}</span>
        </div>
      ) : (
        <span />
      )}

      <div className="command-right">
        {model && model.verdicts_total > 0 && (
          <span className="model-badge" title="Калибровка модели по вердиктам оператора">
            <span className="model-dot" aria-hidden="true" />
            MODEL Δ{model.calibration_delta.toFixed(2)} · {model.verdicts_total} вердикт(ов)
          </span>
        )}

        {onToggleChaos && (
          <button
            type="button"
            className={`chaos-toggle${chaosActive ? ' is-active' : ''}`}
            onClick={onToggleChaos}
            title="Инъекция хаоса (демонстрация антихрупкости)"
          >
            <span className="chaos-glyph" aria-hidden="true">⚡</span>
            {chaosActive ? CHAOS_LABEL[chaos!.mode] : 'CHAOS'}
          </button>
        )}

        {linkMeta && (
          <span
            className={`link-state ${linkMeta.cls}`}
            role="status"
            aria-label={`Канал данных: ${linkMeta.text}`}
          >
            {linkMeta.text}
            {(link === 'stale' || link === 'polling') && typeof dataAgeSec === 'number' && (
              <span className="link-age"> · {dataAgeSec}s</span>
            )}
          </span>
        )}

        <span className="operator-chip">
          <span className="op-avatar" aria-hidden="true">{initials}</span>
          <span className="op-name">{operator}</span>
        </span>
      </div>
    </header>
  );
}
