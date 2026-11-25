import type { ReactElement } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import HomePage from '@/pages/HomePage'
import ResultsPage from '@/pages/ResultsPage'
import HistoryPage from '@/pages/HistoryPage'
import HistoryDetailPage from '@/pages/HistoryDetailPage'
import AdminPage from '@/pages/AdminPage'
import DocsPage from '@/pages/DocsPage'
import AccountPage from '@/pages/AccountPage'
import UsersPage from '@/pages/UsersPage'
import ConnectorsPage from '@/pages/ConnectorsPage'
import { useAuth, type Permission } from '@/auth/context'

/** Routes a role can't use send the user to the history, which every role can browse. */
function Allowed({ permission, children }: { permission: Permission; children: ReactElement }) {
  const { can } = useAuth()
  return can(permission) ? children : <Navigate to="/history" replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Allowed permission="analyze"><HomePage /></Allowed>} />
        <Route path="/results" element={<Allowed permission="analyze"><ResultsPage /></Allowed>} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/history/:id" element={<HistoryDetailPage />} />
        <Route path="/admin" element={<Allowed permission="admin"><AdminPage /></Allowed>} />
        <Route path="/users" element={<Allowed permission="admin"><UsersPage /></Allowed>} />
        <Route path="/connectors" element={<Allowed permission="admin"><ConnectorsPage /></Allowed>} />
        <Route path="/docs" element={<DocsPage />} />
        <Route path="/account" element={<AccountPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
