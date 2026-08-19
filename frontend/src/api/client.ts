// API клиент для TAKT АРМ с TanStack Query

import { QueryClient } from '@tanstack/react-query';
import type {
  Case, AttackChain, Event, EntityBaseline,
  VerdictKind, VerdictResult, ModelSnapshot, ChaosMode, ChaosState,
} from '../types/api';

// Идентификатор текущего оператора смены (для лока и аудита).
export const OPERATOR_ID = 'operator.shift-A';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000, // 30 сек кэш
      refetchOnWindowFocus: true,
      retry: 1,
    },
  },
});

const API_BASE = import.meta.env.VITE_TAKT_API_BASE_URL || 'http://localhost:8090';

// Базовая функция fetch с обработкой ошибок
async function apiRequest<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: 'Неизвестная ошибка' }));
    throw new Error(error.detail || `HTTP ${res.status}`);
  }

  return res.json();
}

// === Кейсы ===

export async function fetchCases(): Promise<Case[]> {
  return apiRequest<Case[]>('/api/v1/cases');
}

export async function fetchCaseById(id: string): Promise<Case> {
  return apiRequest<Case>(`/api/v1/cases/${id}`);
}

export async function updateCaseStatus(id: string, status: Case['status']): Promise<Case> {
  return apiRequest<Case>(`/api/v1/cases/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
}

// === Attack Chain ===

export async function fetchAttackChain(caseId: string): Promise<AttackChain> {
  return apiRequest<AttackChain>(`/api/v1/cases/${caseId}/attack-chain`);
}

// === События ===

export async function fetchEventsByCaseId(caseId: string): Promise<Event[]> {
  return apiRequest<Event[]>(`/api/v1/cases/${caseId}/events`);
}

export async function searchEvents(
  query: string,
  cursor?: string,
  limit: number = 50
): Promise<{ items: Event[]; next_cursor?: string; total_count: number }> {
  const params = new URLSearchParams({ q: query, limit: String(limit) });
  if (cursor) params.set('cursor', cursor);
  
  return apiRequest(`/api/v1/events/search?${params.toString()}`);
}

// === Находки (Findings) ===

export async function addFinding(
  caseId: string,
  entityType: string,
  entityId: string
): Promise<void> {
  return apiRequest('/api/v1/findings', {
    method: 'POST',
    body: JSON.stringify({
      case_id: caseId,
      entity_type: entityType,
      entity_id: entityId,
    }),
  });
}

// === Baseline сущности ===

export async function fetchEntityBaseline(
  entityType: string,
  entityId: string
): Promise<EntityBaseline> {
  return apiRequest<EntityBaseline>(
    `/api/v1/baseline/${entityType}/${encodeURIComponent(entityId)}`
  );
}

// === Стенд: сырой поток и метрика времени оператора ===

export interface RawEvent {
  id: string;
  ts: string;
  source_class: string;
  level: string;
  host_id: string;
  message: string;
  is_attack: boolean;
  attack_step: number | null;
}

export interface BenchmarkResult {
  scenario: string;
  dataset: {
    raw_events_total: number;
    attack_events: number;
    attack_events_ratio: number;
    sources: number;
    attack_graph_nodes: number;
  };
  manual: { breakdown: Record<string, number>; total_sec: number };
  takt: { breakdown: Record<string, number>; total_sec: number };
  result: {
    manual_total_sec: number;
    takt_total_sec: number;
    manual_human: string;
    takt_human: string;
    seconds_saved: number;
    seconds_saved_human: string;
    speedup_x: number;
  };
}

export async function fetchRawEvents(): Promise<{
  items: RawEvent[];
  total_count: number;
  attack_step_count: number;
}> {
  return apiRequest('/api/v1/raw-events?limit=1000');
}

export async function fetchBenchmark(): Promise<BenchmarkResult> {
  return apiRequest<BenchmarkResult>('/api/v1/benchmark');
}

// === Антихрупкость: вердикт, лок, эскалация, модель, аудит, chaos ===

// Петля обучения: вердикт по кейсу корректирует веса инвариантов.
export async function postVerdict(
  caseId: string,
  verdict: VerdictKind,
  reason: string,
  riskFeedback?: 'too_high' | 'too_low' | null
): Promise<VerdictResult> {
  return apiRequest<VerdictResult>(`/api/v1/cases/${caseId}/verdict`, {
    method: 'POST',
    body: JSON.stringify({ verdict, reason, risk_feedback: riskFeedback ?? null, operator: OPERATOR_ID }),
  });
}

// Queue lock: эксклюзивная работа оператора над кейсом.
export async function lockCase(caseId: string): Promise<{ conflict: boolean; operator: string; ts: string }> {
  const res = await fetch(`${API_BASE}/api/v1/cases/${caseId}/lock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ operator: OPERATOR_ID }),
  });
  const data = await res.json();
  if (res.status === 409) return { conflict: true, ...data };
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
  return { conflict: false, ...data };
}

export async function unlockCase(caseId: string): Promise<void> {
  await apiRequest(`/api/v1/cases/${caseId}/unlock`, {
    method: 'POST',
    body: JSON.stringify({ operator: OPERATOR_ID }),
  });
}

export async function escalateCase(caseId: string): Promise<Case> {
  return apiRequest<Case>(`/api/v1/cases/${caseId}/escalate`, {
    method: 'POST',
    body: JSON.stringify({ operator: OPERATOR_ID }),
  });
}

export async function setCaseSeverity(caseId: string, severity: Case['severity']): Promise<Case> {
  return apiRequest<Case>(`/api/v1/cases/${caseId}`, {
    method: 'PATCH',
    body: JSON.stringify({ severity, operator: OPERATOR_ID }),
  });
}

export async function fetchModel(): Promise<ModelSnapshot> {
  return apiRequest<ModelSnapshot>('/api/v1/model');
}

export async function fetchChaos(): Promise<ChaosState> {
  return apiRequest<ChaosState>('/api/v1/chaos');
}

export async function setChaos(mode: ChaosMode): Promise<ChaosState> {
  return apiRequest<ChaosState>('/api/v1/chaos', {
    method: 'POST',
    body: JSON.stringify({ mode }),
  });
}

export async function resetStand(): Promise<void> {
  await apiRequest('/api/v1/reset', { method: 'POST' });
}

// === SSE подписка на обновления кейсов (heartbeat · stale · fallback) ===

// Состояние канала данных. Оператор ВСЕГДА видит реальный режим — это защита
// от «ложного зелёного»: система деградирует явно, а не молча врёт о свежести.
export type LinkState = 'connecting' | 'live' | 'stale' | 'down' | 'polling';

// Если по каналу нет активности (ни кейса, ни heartbeat) дольше этого порога —
// канал считается «замолчавшим» (stale), данные могут быть несвежими.
const STALE_MS = 6_000;
// Период резервного опроса, когда SSE недоступен.
const POLL_MS = 5_000;

export interface SubscribeOptions {
  onStatus?: (state: LinkState) => void;
}

export function subscribeToUpdates(
  onMessage: (data: Case) => void,
  options?: SubscribeOptions
): () => void {
  let es: EventSource | null = null;
  let lastActivity = Date.now();
  let staleTimer: number | undefined;
  let pollTimer: number | undefined;
  let status: LinkState = 'connecting';
  let closed = false;

  const setStatus = (s: LinkState) => {
    if (status === s) return;
    status = s;
    options?.onStatus?.(s);
  };

  const markActivity = () => {
    lastActivity = Date.now();
  };

  // Резервный контур: опрос REST, когда SSE недоступен. Оператор продолжает
  // работать с очередью, а не смотрит в белый экран.
  const startPolling = () => {
    if (pollTimer || closed) return;
    setStatus('polling');
    const tick = async () => {
      try {
        const cases = await fetchCases();
        cases.forEach(onMessage);
        markActivity();
      } catch {
        /* сеть недоступна — сохраняем последний снимок */
      }
    };
    void tick();
    pollTimer = window.setInterval(tick, POLL_MS);
  };
  const stopPolling = () => {
    if (pollTimer) {
      window.clearInterval(pollTimer);
      pollTimer = undefined;
    }
  };

  const connect = () => {
    es = new EventSource(`${API_BASE}/api/v1/stream/cases`);

    es.onopen = () => {
      stopPolling();
      markActivity();
      setStatus('live');
    };

    es.onmessage = (event) => {
      markActivity();
      stopPolling();
      setStatus('live');
      try {
        onMessage(JSON.parse(event.data) as Case);
      } catch {
        // Битый payload (chaos=malformed) — переживаем, а не падаем.
      }
    };

    // Heartbeat: канал жив, даже если новых кейсов нет.
    es.addEventListener('heartbeat', () => {
      markActivity();
      if (status !== 'live') {
        // SSE восстановился — снимаем резервный опрос и возвращаем LIVE.
        stopPolling();
        setStatus('live');
      }
    });

    es.onerror = () => {
      // EventSource пытается переподключиться сам; параллельно поднимаем polling.
      setStatus('down');
      startPolling();
    };
  };

  connect();

  // Детектор «тишины» канала.
  staleTimer = window.setInterval(() => {
    if (closed) return;
    // Пока работает резервный опрос — не трогаем статус.
    if (pollTimer) return;
    const age = Date.now() - lastActivity;
    // Долгая тишина канала → честно поднимаем резервный опрос.
    if (age > STALE_MS * 2) {
      startPolling();
    } else if (age > STALE_MS && status === 'live') {
      // Короткая тишина → помечаем канал устаревшим (без «ложного зелёного»).
      setStatus('stale');
    }
  }, 2_000);

  return () => {
    closed = true;
    es?.close();
    if (staleTimer) window.clearInterval(staleTimer);
    stopPolling();
  };
}
