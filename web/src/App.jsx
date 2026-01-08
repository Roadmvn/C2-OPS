import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout/Layout'
import Dashboard from './pages/Dashboard'
import Agents from './pages/Agents'
import Interact from './pages/Interact'
import Listeners from './pages/Listeners'
import Logs from './pages/Logs'

function App() {
    return (
        <Routes>
            <Route path="/" element={<Layout />}>
                <Route index element={<Navigate to="/dashboard" replace />} />
                <Route path="dashboard" element={<Dashboard />} />
                <Route path="agents" element={<Agents />} />
                <Route path="agents/:id" element={<Interact />} />
                <Route path="listeners" element={<Listeners />} />
                <Route path="logs" element={<Logs />} />
            </Route>
        </Routes>
    )
}

export default App
