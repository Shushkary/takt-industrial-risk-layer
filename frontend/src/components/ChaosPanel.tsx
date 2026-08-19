// Панель инъекции хаоса (hormesis) — управляемый стресс для демонстрации
// антихрупкости: система деградирует явно и предсказуемо, а не падает.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchChaos, setChaos, resetStand } from '../api/client';
import type { ChaosMode } from '../types/api';

interface ChaosOption {
  mode: ChaosMode;
  title: string;
  desc: string;
  expect: string;
}

const OPTIONS: ChaosOption[] = [
  { mode: 'burst', title: 'Всплеск нагрузки', desc: 'Поток кейсов ускоряется до ~2.5/с', expect: 'Очередь не тормозит, дедупликация по ID' },
  { mode: 'drop_source', title: 'Обрыв источника', desc: 'Коллектор замолкает, heartbeat пропадает', expect: 'Канал → STALE, поднимается резервный опрос' },
  { mode: 'dup', title: 'Дубли событий', desc: 'Каждое событие приходит дважды', expect: 'Идемпотентность: строка не задваивается' },
  { mode: 'future', title: 'Рассинхрон времени', desc: 'Метки времени «из будущего» (+3ч)', expect: 'Кейс принят, аномалия времени видна' },
  { mode: 'malformed', title: 'Битый payload', desc: 'В поток вбрасывается некорректный JSON', expect: 'Клиент переживает, а не падает' },
  { mode: 'latency', title: 'Задержка канала', desc: 'Интервал обновлений растёт до 16с', expect: 'Канал жив (heartbeat), не помечается down' },
];

interface ChaosPanelProps {
  open: boolean;
  onClose: () => void;
}

export function ChaosPanel({ open, onClose }: ChaosPanelProps) {
  const queryClient = useQueryClient();

  const { data: chaos } = useQuery({
    queryKey: ['chaos'],
    queryFn: fetchChaos,
    refetchInterval: open ? 2000 : false,
    enabled: open,
  });

  const inject = useMutation({
    mutationFn: (mode: ChaosMode) => setChaos(mode),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['chaos'] }),
  });

  const reset = useMutation({
    mutationFn: resetStand,
    onSuccess: () => {
      queryClient.invalidateQueries();
    },
  });

  if (!open) return null;

  const active = chaos?.mode ?? 'off';

  return (
    <div className="chaos-overlay" role="dialog" aria-label="Инъекция хаоса" onClick={onClose}>
      <aside className="chaos-drawer" onClick={(e) => e.stopPropagation()}>
        <header className="chaos-head">
          <div>
            <h2>Инъекция хаоса</h2>
            <span className="chaos-sub">Hormesis · управляемый стресс делает контур устойчивее</span>
          </div>
          <button className="chaos-close" type="button" onClick={onClose} aria-label="Закрыть">✕</button>
        </header>

        <div className="chaos-status-row">
          <span className="chaos-status-label">Текущий режим</span>
          <span className={`chaos-status-val${active !== 'off' ? ' is-active' : ''}`}>
            {active === 'off' ? 'НОРМА' : active.toUpperCase()}
          </span>
          {chaos && chaos.hits > 0 && <span className="chaos-hits">инъекций: {chaos.hits}</span>}
        </div>

        <div className="chaos-grid">
          {OPTIONS.map((opt) => (
            <button
              key={opt.mode}
              type="button"
              className={`chaos-card${active === opt.mode ? ' is-on' : ''}`}
              onClick={() => inject.mutate(active === opt.mode ? 'off' : opt.mode)}
              disabled={inject.isPending}
            >
              <div className="chaos-card-title">{opt.title}</div>
              <div className="chaos-card-desc">{opt.desc}</div>
              <div className="chaos-card-expect"><span aria-hidden="true">→ </span>{opt.expect}</div>
              <div className="chaos-card-state">{active === opt.mode ? 'АКТИВНО · нажмите чтобы выключить' : 'выключено'}</div>
            </button>
          ))}
        </div>

        <footer className="chaos-foot">
          <button
            type="button"
            className="chaos-off-btn"
            onClick={() => inject.mutate('off')}
            disabled={active === 'off' || inject.isPending}
          >
            Остановить хаос
          </button>
          <button
            type="button"
            className="chaos-reset-btn"
            onClick={() => reset.mutate()}
            disabled={reset.isPending}
            title="Сброс кейсов, весов модели, локов и аудита к исходному состоянию"
          >
            {reset.isPending ? 'Сброс…' : 'Сбросить стенд'}
          </button>
        </footer>
      </aside>
    </div>
  );
}
