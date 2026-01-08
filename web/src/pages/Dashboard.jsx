import { useQuery } from '@tanstack/react-query'
import api from '../services/api'

function Dashboard() {
    const { data: stats, isLoading } = useQuery({
        queryKey: ['stats'],
        queryFn: () => api.get('/api/stats').then(res => res.data)
    })

    if (isLoading) {
        return <div className="loading"><div className="spinner"></div></div>
    }

    return (
        <div>
            {/* Stats Cards */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-value">{stats?.total_agents || 0}</div>
                    <div className="stat-label">Total Agents</div>
                </div>

                <div className="stat-card">
                    <div className="stat-value">{stats?.active_agents || 0}</div>
                    <div className="stat-label">Active</div>
                </div>

                <div className="stat-card warning">
                    <div className="stat-value">{stats?.inactive_agents || 0}</div>
                    <div className="stat-label">Inactive</div>
                </div>

                <div className="stat-card danger">
                    <div className="stat-value">{stats?.dead_agents || 0}</div>
                    <div className="stat-label">Dead</div>
                </div>
            </div>

            {/* Quick Actions */}
            <div className="card">
                <div className="card-header">
                    <h3 className="card-title">Quick Actions</h3>
                </div>
                <div style={{ display: 'flex', gap: '12px' }}>
                    <button className="btn btn-primary">
                        New Listener
                    </button>
                    <button className="btn btn-secondary">
                        Generate Payload
                    </button>
                </div>
            </div>

            {/* Server Info */}
            <div className="card" style={{ marginTop: '20px' }}>
                <div className="card-header">
                    <h3 className="card-title">Server Status</h3>
                </div>
                <table>
                    <tbody>
                        <tr>
                            <td style={{ color: 'var(--text-secondary)' }}>API Server</td>
                            <td><span className="status-badge active">Running</span></td>
                        </tr>
                        <tr>
                            <td style={{ color: 'var(--text-secondary)' }}>Listener (HTTP)</td>
                            <td><span className="status-badge active">Port 443</span></td>
                        </tr>
                        <tr>
                            <td style={{ color: 'var(--text-secondary)' }}>Active Profile</td>
                            <td>default</td>
                        </tr>
                        <tr>
                            <td style={{ color: 'var(--text-secondary)' }}>Pending Tasks</td>
                            <td>{stats?.total_tasks || 0}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    )
}

export default Dashboard
