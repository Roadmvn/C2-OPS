import { useState, useEffect } from 'react'

function Logs() {
    const [logs, setLogs] = useState([
        { time: new Date().toISOString(), level: 'INFO', message: 'Ghost C2 Server started' },
        { time: new Date().toISOString(), level: 'INFO', message: 'HTTP Listener started on port 443' },
        { time: new Date().toISOString(), level: 'INFO', message: 'API Server started on port 3000' },
    ])

    return (
        <div>
            <div className="card">
                <div className="card-header">
                    <h3 className="card-title">Server Logs</h3>
                    <div style={{ display: 'flex', gap: '8px' }}>
                        <button className="btn btn-secondary">Clear</button>
                        <button className="btn btn-secondary">Export</button>
                    </div>
                </div>

                <div className="terminal">
                    <div className="terminal-body" style={{ height: 'calc(100vh - 300px)' }}>
                        <div className="terminal-output">
                            {logs.map((log, idx) => (
                                <div key={idx} style={{ marginBottom: '4px' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>
                                        [{new Date(log.time).toLocaleTimeString()}]
                                    </span>
                                    {' '}
                                    <span style={{
                                        color: log.level === 'ERROR' ? 'var(--status-dead)' :
                                            log.level === 'WARN' ? 'var(--status-inactive)' :
                                                'var(--accent-primary)'
                                    }}>
                                        [{log.level}]
                                    </span>
                                    {' '}
                                    <span>{log.message}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default Logs
