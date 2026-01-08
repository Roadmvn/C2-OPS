import { NavLink, Outlet, useLocation } from 'react-router-dom'

// Icons en SVG inline pour éviter les deps
const Icons = {
    Dashboard: () => (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="3" width="7" height="7" rx="1" />
            <rect x="14" y="3" width="7" height="7" rx="1" />
            <rect x="3" y="14" width="7" height="7" rx="1" />
            <rect x="14" y="14" width="7" height="7" rx="1" />
        </svg>
    ),
    Agents: () => (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="4" y="4" width="16" height="16" rx="2" />
            <path d="M9 9h6M9 13h6M9 17h4" />
        </svg>
    ),
    Listeners: () => (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="2" />
            <path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14" />
        </svg>
    ),
    Logs: () => (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" />
            <polyline points="10 9 9 9 8 9" />
        </svg>
    ),
    Ghost: () => (
        <svg viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2C6.48 2 2 6.48 2 12v8c0 1.1.9 2 2 2h1c1.1 0 2-.9 2-2v-1c0-.55.45-1 1-1s1 .45 1 1v1c0 1.1.9 2 2 2h2c1.1 0 2-.9 2-2v-1c0-.55.45-1 1-1s1 .45 1 1v1c0 1.1.9 2 2 2h1c1.1 0 2-.9 2-2v-8c0-5.52-4.48-10-10-10zm-3 10c-.83 0-1.5-.67-1.5-1.5S8.17 9 9 9s1.5.67 1.5 1.5S9.83 12 9 12zm6 0c-.83 0-1.5-.67-1.5-1.5S14.17 9 15 9s1.5.67 1.5 1.5S15.83 12 15 12z" />
        </svg>
    ),
}

const navItems = [
    { path: '/dashboard', icon: Icons.Dashboard, label: 'Dashboard' },
    { path: '/agents', icon: Icons.Agents, label: 'Agents' },
    { path: '/listeners', icon: Icons.Listeners, label: 'Listeners' },
    { path: '/logs', icon: Icons.Logs, label: 'Logs' },
]

function Layout() {
    const location = useLocation()

    // Trouve le titre de la page actuelle
    const getPageTitle = () => {
        const item = navItems.find(item => location.pathname.startsWith(item.path))
        if (location.pathname.includes('/agents/') && location.pathname !== '/agents') {
            return 'Agent Interaction'
        }
        return item?.label || 'Ghost C2'
    }

    return (
        <div className="app-layout">
            {/* Sidebar */}
            <aside className="sidebar">
                <div className="sidebar-header">
                    <div className="sidebar-logo">
                        <Icons.Ghost />
                        <div>
                            <h1>GHOST</h1>
                            <span>C2 Framework v1.0</span>
                        </div>
                    </div>
                </div>

                <nav className="sidebar-nav">
                    {navItems.map((item) => (
                        <NavLink
                            key={item.path}
                            to={item.path}
                            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                        >
                            <item.icon />
                            {item.label}
                        </NavLink>
                    ))}
                </nav>
            </aside>

            {/* Main Content */}
            <main className="main-content">
                <header className="header">
                    <h2 className="header-title">{getPageTitle()}</h2>
                </header>

                <div className="page-content">
                    <Outlet />
                </div>
            </main>
        </div>
    )
}

export default Layout
