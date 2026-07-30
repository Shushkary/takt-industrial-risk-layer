// Главный компонент приложения TAKT АРМ с роутингом

import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { queryClient } from './api/client';
import { IncidentQueue } from './screens/IncidentQueue';
import { CaseWorkbench } from './screens/CaseWorkbench';
import { Comparison } from './screens/Comparison';
import { cssVariables } from './styles/theme';

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <style>{cssVariables}</style>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<IncidentQueue />} />
          <Route path="/case/:caseId" element={<CaseWorkbench />} />
          <Route path="/compare" element={<Comparison />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
