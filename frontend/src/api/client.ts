// API клиент для TAKT АРМ с TanStack Query

import { QueryClient } from '@tanstack/react-query';
import type { Case, AttackChain, Event, EntityBaseline } from '../types/api';

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

// === SSE подписка на обновления кейсов ===

export function subscribeToUpdates(onMessage: (data: Case) => void): () => void {
  const eventSource = new EventSource(`${API_BASE}/api/v1/stream/cases`);
  
  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (error) {
      console.error('Ошибка парсинга SSE сообщения:', error);
    }
  };
  
  eventSource.onerror = (error) => {
    console.error('SSE ошибка подключения:', error);
  };
  
  // Возвращаем функцию отписки
  return () => eventSource.close();
}
