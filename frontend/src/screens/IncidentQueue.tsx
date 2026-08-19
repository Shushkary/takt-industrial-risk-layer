// Главный экран оператора — плотная SOC-очередь инцидентов.
// Антихрупкость: барбелл риск/импакт/доверие, «тихий хвост» OT, queue lock,
// хоткеи триажа, честное состояние канала (live/stale/polling/down).

import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import {
  fetchCases, subscribeToUpdates, fetchModel, fetchChaos,
  setCaseSeverity, escalateCase, lockCase,
  type LinkState,
} from '../api/client';
import { CommandBar } from '../components/CommandBar';
import { ChaosPanel } from '../components/ChaosPanel';
import { KeyboardShortcuts } from '../components/KeyboardShortcuts';
import { useCaseStore } from '../stores/caseStore';
import { theme } from '../styles/theme';
import type { Case } from '../types/api';

const severityMeta: Record<Case['severity'], { label: string; code: string; color: string; rank: number }> = {
  critical: { label: 'Критический', code: 'CRIT', color: theme.colors.critical, rank: 4 },
  high: { label: 'Высокий', code: 'HIGH', color: theme.colors.high, rank: 3 },
  medium: { label: 'Средний', code: 'MED', color: theme.colors.medium, rank: 2 },
  low: { label: 'Низкий', code: 'LOW', color: theme.colors.low, rank: 1 },
};

const statusMeta: Record<Case['status'], { label: string; color: string; rank: number }> = {
  new: { label: 'Новый', color: theme.colors.new, rank: 3 },
  investigating: { label: 'В работе', color: theme.colors.investigating, rank: 2 },
  resolved: { label: 'Закрыт', color: theme.colors.resolved, rank: 1 },
};

const verdictMeta: Record<'tp' | 'fp' | 'benign', { label: string; color: string }> = {
  tp: { label: 'TP', color: theme.colors.critical },
  fp: { label: 'FP', color: theme.colors.low },
  benign: { label: 'BENIGN', color: theme.colors.textMuted },
};

type SortKey = 'risk' | 'impact' | 'confidence' | 'severity' | 'status' | 'created' | 'updated';
type SortDir = 'asc' | 'desc';

function formatAge(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return 'сейчас';
  if (minutes < 60) return `${minutes}м`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}ч ${minutes % 60}м`;
  const days = Math.floor(hours / 24);
  return `${days}д ${hours % 24}ч`;
}

function sourceTag(item: Case): string {
  return item.severity === 'critical' ? 'ATT&CK/ICS' : 'SIEM-rule';
}

export function IncidentQueue() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const {
    filters,
    toggleSeverityFilter,
    toggleStatusFilter,
    clearFilters,
    focusedIndex,
    setFocusedIndex,
  } = useCaseStore();

  const [liveCases, setLiveCases] = useState<Case[]>([]);
  const [newIds, setNewIds] = useState<Set<string>>(new Set());
  const [link, setLink] = useState<LinkState>('connecting');
  const [dataAgeSec, setDataAgeSec] = useState(0);
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'risk', dir: 'desc' });
  const [query, setQuery] = useState('');
  const [chaosOpen, setChaosOpen] = useState(false);
  const [flash, setFlash] = useState<string | null>(null);
  const tableBodyRef = useRef<HTMLTableSectionElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const { data: initialCases, isLoading } = useQuery({
    queryKey: ['cases'],
    queryFn: fetchCases,
  });

  const { data: model } = useQuery({
    queryKey: ['model'],
    queryFn: fetchModel,
    refetchInterval: 4000,
  });

  const { data: chaos } = useQuery({
    queryKey: ['chaos'],
    queryFn: fetchChaos,
    refetchInterval: 3000,
  });

  // Мутации триажа (клавиатура-first).
  const severityMut = useMutation({
    mutationFn: ({ id, sev }: { id: string; sev: Case['severity'] }) => setCaseSeverity(id, sev),
    onSuccess: (_d, v) => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      showFlash(`Severity → ${severityMeta[v.sev].code}`);
    },
  });
  const escalateMut = useMutation({
    mutationFn: (id: string) => escalateCase(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      showFlash('Эскалировано на L2');
    },
  });
  const lockMut = useMutation({
    mutationFn: (id: string) => lockCase(id),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      showFlash(res.conflict ? `Занято: ${res.operator}` : 'Взято в работу');
    },
  });

  function showFlash(msg: string) {
    setFlash(msg);
    window.setTimeout(() => setFlash(null), 1800);
  }

  useEffect(() => {
    return subscribeToUpdates(
      (updatedCase) => {
        setLiveCases((previous) => {
          const index = previous.findIndex((item) => item.id === updatedCase.id);
          if (index < 0) return [updatedCase, ...previous];
          const next = [...previous];
          next[index] = updatedCase;
          return next;
        });
        setNewIds((prev) => new Set(prev).add(updatedCase.id));
        window.setTimeout(() => {
          setNewIds((prev) => {
            const next = new Set(prev);
            next.delete(updatedCase.id);
            return next;
          });
        }, 1200);
      },
      { onStatus: (state) => setLink(state) }
    );
  }, []);

  // Возраст данных: 0 пока канал live, иначе растёт (для честного stale-индикатора).
  useEffect(() => {
    const id = window.setInterval(() => {
      setDataAgeSec((prev) => (link === 'live' ? 0 : prev + 1));
    }, 1000);
    return () => window.clearInterval(id);
  }, [link]);

  const allCases = useMemo(() => {
    const byId = new Map((initialCases ?? []).map((item) => [item.id, item]));
    // Побеждает более свежая версия по updated_at: снимок из живого канала
    // не должен «затирать» только что перечитанный после триажа результат.
    liveCases.forEach((item) => {
      const existing = byId.get(item.id);
      if (!existing || item.updated_at >= existing.updated_at) byId.set(item.id, item);
    });
    return Array.from(byId.values());
  }, [initialCases, liveCases]);

  const sortedCases = useMemo(() => {
    const dir = sort.dir === 'asc' ? 1 : -1;
    const value = (item: Case): number => {
      switch (sort.key) {
        case 'risk': return item.risk_score;
        case 'impact': return item.impact_score ?? 0;
        case 'confidence': return item.confidence ?? 0;
        case 'severity': return severityMeta[item.severity].rank;
        case 'status': return statusMeta[item.status].rank;
        case 'created': return new Date(item.created_at).getTime();
        case 'updated': return new Date(item.updated_at).getTime();
      }
    };
    const q = query.trim().toLowerCase();
    return allCases
      .filter((item) => {
        if (filters.severity && !filters.severity.includes(item.severity)) return false;
        if (filters.status && !filters.status.includes(item.status)) return false;
        if (q && !(`${item.id} ${item.title}`.toLowerCase().includes(q))) return false;
        return true;
      })
      .sort((a, b) => {
        const primary = (value(a) - value(b)) * dir;
        if (primary !== 0) return primary;
        return b.risk_score - a.risk_score;
      });
  }, [allCases, filters, sort, query]);

  const criticalCount = allCases.filter((item) => item.severity === 'critical').length;
  const activeCount = allCases.filter((item) => item.status === 'investigating').length;
  const tailCount = allCases.filter((item) => item.tail_risk && item.risk_score < 0.6).length;

  // Автопрокрутка выбранной строки в зону видимости (навигация j/k).
  useEffect(() => {
    const row = tableBodyRef.current?.querySelector<HTMLElement>(`[data-index="${focusedIndex}"]`);
    row?.scrollIntoView({ block: 'nearest' });
  }, [focusedIndex]);

  // Хоткеи триажа: 1-4 severity · a взять · e эскалация · / поиск · x chaos.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
        if (e.key === 'Escape') el.blur();
        return;
      }
      const item = sortedCases[focusedIndex];
      switch (e.key) {
        case '1': if (item) { e.preventDefault(); severityMut.mutate({ id: item.id, sev: 'critical' }); } break;
        case '2': if (item) { e.preventDefault(); severityMut.mutate({ id: item.id, sev: 'high' }); } break;
        case '3': if (item) { e.preventDefault(); severityMut.mutate({ id: item.id, sev: 'medium' }); } break;
        case '4': if (item) { e.preventDefault(); severityMut.mutate({ id: item.id, sev: 'low' }); } break;
        case 'a': case 'A': if (item) { e.preventDefault(); lockMut.mutate(item.id); } break;
        case 'e': case 'E': if (item) { e.preventDefault(); escalateMut.mutate(item.id); } break;
        case '/': e.preventDefault(); searchRef.current?.focus(); break;
        case 'x': case 'X': e.preventDefault(); setChaosOpen((o) => !o); break;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [sortedCases, focusedIndex, severityMut, escalateMut, lockMut]);

  const toggleSort = (key: SortKey) => {
    setSort((prev) =>
      prev.key === key
        ? { key, dir: prev.dir === 'desc' ? 'asc' : 'desc' }
        : { key, dir: 'desc' }
    );
  };

  const sortArrow = (key: SortKey) =>
    sort.key === key ? <span className="sort-arrow">{sort.dir === 'desc' ? '▼' : '▲'}</span> : null;

  const filtersActive = Boolean(filters.severity || filters.status || query);

  return (
    <main className="console">
      <CommandBar
        link={link}
        dataAgeSec={dataAgeSec}
        chaos={chaos}
        onToggleChaos={() => setChaosOpen(true)}
        model={model ? { verdicts_total: model.verdicts_total, calibration_delta: model.calibration_delta } : undefined}
      />

      <div className="section-head">
        <h1>Очередь инцидентов</h1>
        <span className="section-sub">
          Промышленный сегмент · приоритизация по контекстному риску, импакту и корреляции
        </span>
        <span className="toolbar-spacer" />
        <a
          className="primary-link"
          href={`${import.meta.env.BASE_URL}compare`}
          onClick={(event) => {
            event.preventDefault();
            navigate('/compare');
          }}
        >
          Сравнить режимы <span aria-hidden="true">→</span>
        </a>
      </div>

      <section className="kpi-strip" aria-label="Сводка очереди">
        <KpiTile label="Всего кейсов" value={allCases.length} note="Синтетический стенд" color={theme.colors.accent} />
        <KpiTile label="Критические" value={criticalCount} note="Немедленный triage" color={theme.colors.critical} />
        <KpiTile label="В работе" value={activeCount} note="Назначены оператору" color={theme.colors.investigating} />
        <KpiTile label="Тихий хвост OT" value={tailCount} note="Низкий риск · высокий импакт" color={theme.colors.high} />
      </section>

      <section className="queue-toolbar" aria-label="Фильтры, поиск и сортировка">
        <div className="filter-group">
          <span className="filter-label">Серьёзность</span>
          {(Object.keys(severityMeta) as Case['severity'][]).map((severity) => (
            <FilterChip
              key={severity}
              label={severityMeta[severity].label}
              active={filters.severity?.includes(severity) ?? false}
              color={severityMeta[severity].color}
              onClick={() => toggleSeverityFilter(severity)}
            />
          ))}
        </div>

        <div className="filter-group">
          <span className="filter-label">Состояние</span>
          {(Object.keys(statusMeta) as Case['status'][]).map((status) => (
            <FilterChip
              key={status}
              label={statusMeta[status].label}
              active={filters.status?.includes(status) ?? false}
              color={statusMeta[status].color}
              onClick={() => toggleStatusFilter(status)}
            />
          ))}
        </div>

        <span className="toolbar-spacer" />

        <input
          ref={searchRef}
          className="queue-search"
          type="search"
          placeholder="Поиск  /  "
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Поиск по кейсам"
        />
        <span className="result-count">
          <strong>{sortedCases.length}</strong> / {allCases.length}
        </span>
        {filtersActive && (
          <button className="filter-reset" type="button" onClick={() => { clearFilters(); setQuery(''); }}>
            Сбросить
          </button>
        )}
      </section>

      <div className="queue-hint">
        <span className="kbd-combo"><kbd>J</kbd><kbd>K</kbd> выбор</span>
        <span className="kbd-combo"><kbd>Enter</kbd> открыть</span>
        <span className="kbd-combo"><kbd>1</kbd>–<kbd>4</kbd> severity</span>
        <span className="kbd-combo"><kbd>A</kbd> взять</span>
        <span className="kbd-combo"><kbd>E</kbd> эскалация</span>
        <span className="kbd-combo"><kbd>/</kbd> поиск</span>
        <span className="kbd-combo"><kbd>X</kbd> chaos</span>
        {flash && <span className="queue-flash" role="status">{flash}</span>}
      </div>

      {isLoading ? (
        <div className="empty-state">Загрузка очереди…</div>
      ) : sortedCases.length === 0 ? (
        <div className="empty-state">
          <div className="empty-glyph">∅</div>
          По выбранным фильтрам кейсов нет.
        </div>
      ) : (
        <div className="incident-table-wrap">
          <table className="incident-table">
            <thead>
              <tr>
                <th className="cell-sev sortable" onClick={() => toggleSort('severity')}>
                  SEV{sortArrow('severity')}
                </th>
                <th className="sortable" onClick={() => toggleSort('risk')}>
                  Риск{sortArrow('risk')}
                </th>
                <th className="col-impact sortable" onClick={() => toggleSort('impact')}>
                  Импакт{sortArrow('impact')}
                </th>
                <th className="col-conf sortable" onClick={() => toggleSort('confidence')}>
                  Дов.{sortArrow('confidence')}
                </th>
                <th>Кейс</th>
                <th>Заголовок</th>
                <th className="col-source">Источник</th>
                <th className="col-findings num">Находки</th>
                <th className="sortable" onClick={() => toggleSort('status')}>
                  Статус{sortArrow('status')}
                </th>
                <th className="col-age sortable" onClick={() => toggleSort('created')}>
                  Возраст{sortArrow('created')}
                </th>
                <th className="sortable" onClick={() => toggleSort('updated')}>
                  Обновлён{sortArrow('updated')}
                </th>
              </tr>
            </thead>
            <tbody ref={tableBodyRef}>
              {sortedCases.map((item, index) => {
                const severity = severityMeta[item.severity];
                const status = statusMeta[item.status];
                const risk = Math.round(item.risk_score * 100);
                const impact = Math.round((item.impact_score ?? 0) * 100);
                const conf = item.confidence ?? 0;
                const isFocused = focusedIndex === index;
                const isNew = newIds.has(item.id);
                const isTail = item.tail_risk && item.risk_score < 0.6;
                const locked = Boolean(item.lock);

                return (
                  <tr
                    key={item.id}
                    data-index={index}
                    className={`incident-row${isFocused ? ' is-focused' : ''}${isNew ? ' is-new' : ''}${isTail ? ' is-tail' : ''}`}
                    onClick={() => {
                      setFocusedIndex(index);
                      navigate(`/case/${item.id}`);
                    }}
                    onMouseEnter={() => setFocusedIndex(index)}
                    aria-label={`${severity.label}: ${item.title}. Риск ${risk}, импакт ${impact}, доверие ${conf.toFixed(2)}. Статус ${status.label}`}
                    style={{ '--severity-color': severity.color } as React.CSSProperties}
                  >
                    <td className="cell-sev">
                      <span className="led" title={severity.label} />
                    </td>
                    <td className="cell-risk">
                      <div className="risk-figure">
                        <span className="risk-num">{risk}</span>
                        <span className="risk-mini" aria-hidden="true">
                          <span style={{ '--risk-width': `${risk}%` } as React.CSSProperties} />
                        </span>
                      </div>
                    </td>
                    <td className="cell-impact col-impact">
                      <div className="risk-figure">
                        <span className="impact-num">{impact}</span>
                        <span className="impact-mini" aria-hidden="true">
                          <span style={{ '--risk-width': `${impact}%` } as React.CSSProperties} />
                        </span>
                      </div>
                    </td>
                    <td className="cell-conf col-conf">
                      <span className={`conf-badge${conf < 0.5 ? ' is-low' : ''}`} title={`доверие ${conf.toFixed(2)} · наблюдений: ${item.observations ?? '—'}`}>
                        {conf.toFixed(2)}
                      </span>
                    </td>
                    <td className="cell-id">
                      {locked && <span className="lock-glyph" title={`В работе: ${item.lock?.operator}`}>🔒</span>}
                      {item.id}
                    </td>
                    <td className="cell-title">
                      <span className="title-line">{item.title}</span>
                      {isTail && <span className="tail-chip" title="Низкая вероятность, высокий импакт на АСУ ТП">тихий хвост OT</span>}
                    </td>
                    <td className="cell-source col-source">
                      <span className="tag">{sourceTag(item)}</span>
                    </td>
                    <td className="cell-findings col-findings num">{item.findings.length}</td>
                    <td>
                      {item.verdict ? (
                        <span className="verdict-pill" style={{ '--status-color': verdictMeta[item.verdict.verdict].color } as React.CSSProperties}>
                          {verdictMeta[item.verdict.verdict].label}
                        </span>
                      ) : (
                        <span className="status-pill" style={{ '--status-color': status.color } as React.CSSProperties}>
                          {status.label}
                        </span>
                      )}
                    </td>
                    <td className="cell-age col-age">{formatAge(item.created_at)}</td>
                    <td className="cell-age">{format(new Date(item.updated_at), 'dd.MM HH:mm')}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <KeyboardShortcuts cases={sortedCases} />
      <ChaosPanel open={chaosOpen} onClose={() => setChaosOpen(false)} />

      <footer className="queue-footer">
        <span>TAKT PT · демонстрационная среда · IEC 60870-5-104 · MITRE ATT&amp;CK for ICS</span>
        <span>{sortedCases.length} инцидентов в фокусе</span>
      </footer>
    </main>
  );
}

function KpiTile({
  label,
  value,
  note,
  color,
}: {
  label: string;
  value: number;
  note: string;
  color: string;
}) {
  return (
    <div className="kpi-tile" style={{ '--kpi-color': color } as React.CSSProperties}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-note">{note}</div>
    </div>
  );
}

function FilterChip({
  label,
  active,
  color,
  onClick,
}: {
  label: string;
  active: boolean;
  color: string;
  onClick: () => void;
}) {
  return (
    <button
      className="filter-chip"
      type="button"
      aria-pressed={active}
      onClick={onClick}
      style={{ '--chip-color': color } as React.CSSProperties}
    >
      {label}
    </button>
  );
}
