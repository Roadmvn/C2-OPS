function Listeners() {
    return (
        <div>
            <div className="card">
                <div className="card-header">
                    <h3 className="card-title">Active Listeners</h3>
                    <button className="btn btn-primary">+ New Listener</button>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Port</th>
                            <th>Host</th>
                            <th>Profile</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>HTTP</td>
                            <td>443</td>
                            <td>0.0.0.0</td>
                            <td>default</td>
                            <td><span className="status-badge active">Running</span></td>
                            <td>
                                <button className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '0.75rem' }}>
                                    Stop
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            {/* Profiles */}
            <div className="card" style={{ marginTop: '20px' }}>
                <div className="card-header">
                    <h3 className="card-title">Available Profiles</h3>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '16px' }}>
                    {['default', 'jquery-cdn', 'microsoft-update'].map(profile => (
                        <div key={profile} className="card" style={{ padding: '16px' }}>
                            <h4 style={{ marginBottom: '8px' }}>{profile}</h4>
                            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                {profile === 'default' && 'Minimal HTTP traffic'}
                                {profile === 'jquery-cdn' && 'Mimics jQuery CDN requests'}
                                {profile === 'microsoft-update' && 'Mimics Windows Update traffic'}
                            </p>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    )
}

export default Listeners
