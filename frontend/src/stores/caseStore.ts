// Zustand store для управления состоянием АРМ

import { create } from 'zustand';
import type { Case } from '../types/api';

interface CaseFilters {
  severity?: Case['severity'][];
  status?: Case['status'][];
}

interface CaseStore {
  // Текущий выбранный кейс
  selectedCaseId: string | null;
  setSelectedCaseId: (id: string | null) => void;
  
  // Выбранная сущность в графе/таймлайне
  selectedEntity: {
    type: 'host' | 'user' | 'process' | 'address' | 'artifact';
    id: string;
  } | null;
  setSelectedEntity: (entity: CaseStore['selectedEntity']) => void;
  
  // Фильтры для очереди инцидентов
  filters: CaseFilters;
  setFilters: (filters: CaseFilters) => void;
  toggleSeverityFilter: (severity: Case['severity']) => void;
  toggleStatusFilter: (status: Case['status']) => void;
  clearFilters: () => void;
  
  // Индекс фокуса для навигации j/k
  focusedIndex: number;
  setFocusedIndex: (index: number) => void;
  incrementFocus: () => void;
  decrementFocus: () => void;
}

export const useCaseStore = create<CaseStore>((set) => ({
  selectedCaseId: null,
  setSelectedCaseId: (id) => set({ selectedCaseId: id }),
  
  selectedEntity: null,
  setSelectedEntity: (entity) => set({ selectedEntity: entity }),
  
  filters: {},
  setFilters: (filters) => set({ filters }),
  
  toggleSeverityFilter: (severity) =>
    set((state) => {
      const current = state.filters.severity || [];
      const newSeverity = current.includes(severity)
        ? current.filter((s) => s !== severity)
        : [...current, severity];
      return {
        filters: {
          ...state.filters,
          severity: newSeverity.length > 0 ? newSeverity : undefined,
        },
      };
    }),
  
  toggleStatusFilter: (status) =>
    set((state) => {
      const current = state.filters.status || [];
      const newStatus = current.includes(status)
        ? current.filter((s) => s !== status)
        : [...current, status];
      return {
        filters: {
          ...state.filters,
          status: newStatus.length > 0 ? newStatus : undefined,
        },
      };
    }),
  
  clearFilters: () => set({ filters: {} }),
  
  focusedIndex: 0,
  setFocusedIndex: (index) => set({ focusedIndex: index }),
  incrementFocus: () => set((state) => ({ focusedIndex: state.focusedIndex + 1 })),
  decrementFocus: () =>
    set((state) => ({
      focusedIndex: Math.max(0, state.focusedIndex - 1),
    })),
}));
