export type IncidentStatus = 'Разбор' | 'Подтверждён' | 'Ложное срабатывание' | 'Ожидаемое поведение' | 'Закрыт'
export type DemoScenarioId =
  | 'moscow-apartment-boiler'
  | 'moscow-hospital-boiler'
  | 'moscow-industrial-boiler'
  | 'moscow-heat-network'
  | 'moscow-central-heat-point'
export type DemoSegmentMode = 'NORMAL' | 'DEGRADED' | 'AIR-GAP' | 'STORM'
export type DemoShiftPhase = 'WORK' | 'NIGHT' | 'MAINT'
export type DemoNodeKind = 'dispatch' | 'engineering' | 'server' | 'plc' | 'gateway' | 'archive' | 'sensor' | 'cabinet'
export type DemoNodeState = 'normal' | 'warning' | 'critical'

export type DemoScenario = {
  id: DemoScenarioId
  title: string
  facility: string
  region: 'Москва'
  connectionPoint: string
  description: string
  serviceContext: string
}

export type DemoIncident = {
  id: string
  time: string
  node: string
  invariant: string
  risk: number
  phase: string
  status: IncidentStatus
  operator: string
  summary: string
  serviceDesk?: string
  scenarioId: DemoScenarioId
  mode: DemoSegmentMode
  phaseKey: DemoShiftPhase
}

export type DemoNode = {
  id: string
  label: string
  kind: DemoNodeKind
  x: number
  y: number
  state: DemoNodeState
  lastSeenDays: number
  scenarioId: DemoScenarioId
  modes: DemoSegmentMode[]
  phases: DemoShiftPhase[]
}

export type DemoLinkCategory = 'engineering_bypass' | 'plc' | 'gateway' | 'regular'

export type DemoLink = {
  id: string
  label: string
  from: string
  to: string
  state: DemoNodeState
  lastSeenDays: number
  categories: DemoLinkCategory[]
  scenarioId: DemoScenarioId
  detail: string
  modes: DemoSegmentMode[]
  phases: DemoShiftPhase[]
}

export type DemoRiskControls = {
  engineeringAccess: number
  pollingInstability: number
  telemetryFreshnessLoss: number
  missingWorkOrder: number
}
