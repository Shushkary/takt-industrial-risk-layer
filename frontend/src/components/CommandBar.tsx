// Верхняя командная строка SOC-консоли: бренд, часы UTC, состояние канала, оператор.

import { useEffect, useState } from 'react';

type LinkState = 'live' | 'down' | 'idle';

interface CommandBarProps {
  /** Состояние SSE-канала. Если не передано — индикатор канала скрыт. */
  link?: LinkState;
  /** Показывать ли часы UTC (по умолчанию да). */
  showClock?: boolean;
  /** Имя оператора смены. */
  operator?: string;
}

function pad(value: number): string {
  return String(value).padStart(2, '0');
}

export function CommandBar({ link, showClock = true, operator = 'operator.shift-A' }: CommandBarProps) {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const utc = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())}`;
  const dateUtc = `${pad(now.getUTCDate())}.${pad(now.getUTCMonth() + 1)}.${now.getUTCFullYear()}`;
  const initials = operator.replace(/[^a-zа-я]/gi, '').slice(0, 2).toUpperCase() || 'OP';

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
        {link && (
          <span
            className={`link-state${link === 'down' ? ' is-down' : ''}`}
            role="status"
            aria-label={link === 'live' ? 'Канал SSE активен' : link === 'down' ? 'Канал SSE потерян' : 'Ожидание канала'}
          >
            {link === 'live' ? 'LIVE · SSE' : link === 'down' ? 'OFFLINE' : 'CONNECTING'}
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
