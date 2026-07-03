import { create } from 'zustand'

export type SegmentMode = 'NORMAL' | 'DEGRADED' | 'AIR-GAP' | 'STORM'
export type ShiftPhase = 'WORK' | 'NIGHT' | 'MAINT'

type UiState = {
  segmentMode: SegmentMode
  shiftPhase: ShiftPhase
  partialObservability: number
  setSegmentMode: (m: SegmentMode) => void
  setShiftPhase: (p: ShiftPhase) => void
  setPartialObservability: (v: number) => void
}

export const useUiStore = create<UiState>((set) => ({
  segmentMode: 'NORMAL',
  shiftPhase: 'WORK',
  partialObservability: 0,
  setSegmentMode: (segmentMode) =>
    set({
      segmentMode,
      partialObservability: segmentMode === 'NORMAL' ? 0 : segmentMode === 'DEGRADED' ? 0.34 : segmentMode === 'AIR-GAP' ? 0.58 : 0.18,
    }),
  setShiftPhase: (shiftPhase) => set({ shiftPhase }),
  setPartialObservability: (partialObservability) => set({ partialObservability }),
}))
