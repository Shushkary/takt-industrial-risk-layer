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
