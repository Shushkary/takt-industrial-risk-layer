import { Route, Routes } from 'react-router-dom'
import { AppShell } from './layout/AppShell'
import { SegmentOverview } from './pages/SegmentOverview'
import { IncidentQueue } from './pages/IncidentQueue'
import { CaseDetail } from './pages/CaseDetail'
import { InvariantLibrary } from './pages/InvariantLibrary'
import { TopologyMap } from './pages/TopologyMap'
import { SettingsAudit } from './pages/SettingsAudit'
import { UnifiedSearch } from './pages/UnifiedSearch'

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<SegmentOverview />} />
        <Route path="incidents" element={<IncidentQueue />} />
        <Route path="cases/:id" element={<CaseDetail />} />
        <Route path="search" element={<UnifiedSearch />} />
        <Route path="invariants" element={<InvariantLibrary />} />
        <Route path="topology" element={<TopologyMap />} />
        <Route path="settings" element={<SettingsAudit />} />
      </Route>
    </Routes>
  )
}
