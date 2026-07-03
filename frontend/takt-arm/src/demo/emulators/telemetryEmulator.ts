import { demoIncidents, demoLinks, demoNodes } from '../database/heatEnergyDatabase'
import type {
  DemoIncident,
  DemoLink,
  DemoNode,
  DemoRiskControls,
  DemoScenarioId,
  DemoSegmentMode,
  DemoShiftPhase,
} from '../domain'

export const defaultRiskControls: DemoRiskControls = {
  engineeringAccess: 65,
  pollingInstability: 45,
  telemetryFreshnessLoss: 30,
  missingWorkOrder: 55,
}

export type DemoSelection = {
  scenarioId: DemoScenarioId
  segmentMode: DemoSegmentMode
  shiftPhase: DemoShiftPhase
  riskControls: DemoRiskControls
}

function clampRisk(value: number): number {
  return Math.max(0.05, Math.min(0.99, value))
}

export function emulateIncidentRisk(incident: DemoIncident, controls: DemoRiskControls): number {
  const accessFactor = incident.invariant.includes('доступ') || incident.invariant.includes('обход')
    ? controls.engineeringAccess / 100
    : 0
  const pollingFactor = incident.invariant.includes('опрос') ? controls.pollingInstability / 100 : 0
  const freshnessFactor = incident.invariant.includes('свежести') ? controls.telemetryFreshnessLoss / 100 : 0
  const workOrderFactor = incident.serviceDesk ? 0 : controls.missingWorkOrder / 100
  return clampRisk(incident.risk + accessFactor * 0.08 + pollingFactor * 0.07 + freshnessFactor * 0.07 + workOrderFactor * 0.06)
}

export function selectDemoIncidents(selection: DemoSelection): DemoIncident[] {
  return demoIncidents
    .filter(
      (incident) =>
        incident.scenarioId === selection.scenarioId &&
        incident.mode === selection.segmentMode &&
        incident.phaseKey === selection.shiftPhase,
    )
    .map((incident) => ({
      ...incident,
      risk: emulateIncidentRisk(incident, selection.riskControls),
    }))
}

export function selectDemoTopology(
  selection: DemoSelection & { rangeDays: number; linkCategories: DemoLink['categories'] | [] },
): { nodes: DemoNode[]; links: DemoLink[]; selectedLinks: DemoLink[] } {
  const baseLinks = demoLinks.filter((link) => {
    return (
      link.scenarioId === selection.scenarioId &&
      link.lastSeenDays <= selection.rangeDays &&
      link.modes.includes(selection.segmentMode) &&
      link.phases.includes(selection.shiftPhase)
    )
  })
  const selectedLinks =
    selection.linkCategories.length === 0
      ? baseLinks
      : baseLinks.filter((link) => selection.linkCategories.some((category) => link.categories.includes(category)))
  const links = selectedLinks.length > 0 ? selectedLinks : baseLinks
  const linkedNodeIds = new Set(links.flatMap((link) => [link.from, link.to]))
  const nodes = demoNodes.filter((node) => {
    if (node.scenarioId !== selection.scenarioId) {
      return false
    }
    const participatesInVisibleLink = linkedNodeIds.has(node.id)
    const visibleByModeAndRange =
      node.lastSeenDays <= selection.rangeDays &&
      node.modes.includes(selection.segmentMode) &&
      node.phases.includes(selection.shiftPhase)
    return participatesInVisibleLink || visibleByModeAndRange
  })
  return { nodes, links, selectedLinks }
}

export function emulateRiskSummary(controls: DemoRiskControls): { key: keyof DemoRiskControls; label: string; value: number }[] {
  return [
    { key: 'engineeringAccess', label: 'Доступ инженера', value: controls.engineeringAccess },
    { key: 'pollingInstability', label: 'Нестабильность опроса', value: controls.pollingInstability },
    { key: 'telemetryFreshnessLoss', label: 'Свежесть телеметрии', value: controls.telemetryFreshnessLoss },
    { key: 'missingWorkOrder', label: 'Отсутствие наряда', value: controls.missingWorkOrder },
  ]
}
