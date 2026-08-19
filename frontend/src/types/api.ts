// TypeScript интерфейсы для API TAKT АРМ

export interface Case {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'new' | 'investigating' | 'resolved';
  created_at: string; // ISO 8601
  updated_at: string;
  title: string;
  risk_score: number;
  xai_summary: string;
  findings: Finding[];

  // --- Антихрупкость: барбелл риск / импакт / доверие ---
  base_risk_score?: number;   // риск до пересчёта весами модели
  impact_score?: number;      // физический импакт на АСУ ТП (0..1)
  confidence?: number;        // доверие к скору (растёт с числом наблюдений)
  observations?: number;      // сколько событий обосновывают скор
  tail_risk?: boolean;        // «тихий хвост»: низкая вероятность, высокий импакт
  invariants?: string[];      // сработавшие инварианты (петля обучения)
  invariant_factor?: number;  // текущий множитель весов инвариантов
  falsifiers?: string[];      // via negativa: чем можно отменить вердикт
  escalated?: boolean;

  verdict?: CaseVerdict;      // вынесенный вердикт
  lock?: CaseLock;            // текущий лок
}

export type VerdictKind = 'tp' | 'fp' | 'benign';

export interface CaseVerdict {
  verdict: VerdictKind;
  reason: string;
  risk_feedback?: 'too_high' | 'too_low' | null;
  operator: string;
  ts: string;
}

export interface CaseLock {
  operator: string;
  ts: string;
}

export interface VerdictResult {
  case: Case;
  adjusted_invariants: { invariant: string; before: number; after: number }[];
  affected_cases: string[];
}

export interface ModelSnapshot {
  weights: Record<string, number>;
  confirms: Record<string, number>;
  rejects: Record<string, number>;
  verdicts_total: number;
  verdict_counts: Partial<Record<VerdictKind, number>>;
  calibration_delta: number;
}

export type ChaosMode =
  | 'off' | 'burst' | 'drop_source' | 'dup' | 'future' | 'malformed' | 'latency';

export interface ChaosState {
  mode: ChaosMode;
  since: string | null;
  hits: number;
}

export interface Finding {
  id: string;
  entity_type: 'host' | 'user' | 'process' | 'address' | 'artifact';
  entity_id: string;
  added_at: string;
}

export interface Event {
  id: string;
  source_class: string;
  host_id?: string;
  user_id?: string;
  process?: string;
  address?: string;
  artifact?: string;
  ts: string; // ISO 8601
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface AttackChain {
  nodes: Node[];
  edges: Edge[];
}

export interface Node {
  id: string;
  type: 'host' | 'user' | 'process' | 'address' | 'artifact';
  label: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  position?: { x: number; y: number };
}

export interface Edge {
  id: string;
  source: string;
  target: string;
  correlation_reason: string;
}

export interface EntityBaseline {
  entity_type: string;
  entity_id: string;
  z_scores: number[]; // Последние N z-score значений для sparkline
  mean: number;
  stddev: number;
}
