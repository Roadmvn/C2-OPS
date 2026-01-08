import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'

function Agents() {
    const navigate = useNavigate()

    const { data: agents, isLoading } = useQuery({
        queryKey: ['agents'],
        queryFn: () => api.get('/api/agents').then(res => res.data)
    })

    if (isLoading) {
        return <div className="loading"><div className="spinner"></div></div>
    }

    const formatDate = (dateStr) => {
        const date = new Date(dateStr)
        const now = new Date()
        const diff = Math.floor((now - date) / 1000)

        if (diff < 60) return `${diff}s ago`
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
        return date.toLocaleDateString()
    }

    return (
        <div>
            {agents?.length === 0 ? (
                <div className="card" style={{ textAlign: 'center', padding: '60px 20px' }}>
                    <div style={{ fontSize: '3rem', marginBottom: '16px', opacity: 0.3 }}>👻</div>
                    <h3 style={{ marginBottom: '8px' }}>No Agents Connected</h3>
                    <p style={{ color: 'var(--text-muted)' }}>
                        Waiting for agents to check in...
                    </p>
                </div>
            ) : (
                <div>
                    {agents?.map((agent) => (
                        <div
                            key={agent.id}
                            className="agent-card"
                            onClick={() => navigate(`/agents/${agent.id}`)}
                        >
                            <div className="agent-info">
                                <div className="agent-icon">
                                    {agent.os?.toLowerCase().includes('windows') ? '💻' : '🖥️'}
                                </div>
                                <div className="agent-details">
                                    <h3>{agent.username}@{agent.hostname}</h3>
                                    <p>{agent.id.slice(0, 12)}... | {agent.os} {agent.arch}</p>
                                </div>
                            </div>
                            <div className="agent-meta">
                                <span className={`status-badge ${agent.status}`}>
                                    {agent.status}
                                </span>
                                <p className="last-seen">{formatDate(agent.last_seen)}</p>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    )
}

export default Agents
