import { create } from 'zustand'
import type { DemoRiskControls, DemoScenarioId } from '../domain'
import { defaultRiskControls } from '../emulators/telemetryEmulator'

type DemoStore = {
  scenarioId: DemoScenarioId
  riskControls: DemoRiskControls
  setScenarioId: (scenarioId: DemoScenarioId) => void
  setRiskControl: (key: keyof DemoRiskControls, value: number) => void
}

export const useDemoStore = create<DemoStore>((set) => ({
  scenarioId: 'moscow-apartment-boiler',
  riskControls: defaultRiskControls,
  setScenarioId: (scenarioId) => set({ scenarioId }),
  setRiskControl: (key, value) =>
    set((state) => ({
      riskControls: {
        ...state.riskControls,
        [key]: Math.max(0, Math.min(100, value)),
      },
    })),
}))
