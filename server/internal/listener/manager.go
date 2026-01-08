/*
 * manager.go - Gestionnaire de listeners
 */
package listener

import (
	"ghost-server/internal/profile"
	"ghost-server/internal/session"
	"ghost-server/internal/task"
)

// Manager gère les différents listeners
type Manager struct {
	sessions *session.Manager
	tasks    *task.Queue
	profile  *profile.Profile
	http     *HTTPListener
}

// NewManager crée un nouveau gestionnaire de listeners
func NewManager(sessions *session.Manager, tasks *task.Queue, prof *profile.Profile) *Manager {
	return &Manager{
		sessions: sessions,
		tasks:    tasks,
		profile:  prof,
	}
}

// StartHTTP démarre un listener HTTP
func (m *Manager) StartHTTP(port int) error {
	m.http = NewHTTPListener(m.sessions, m.tasks, m.profile)
	return m.http.Start(port)
}

// StartHTTPS démarre un listener HTTPS
func (m *Manager) StartHTTPS(port int, certFile, keyFile string) error {
	m.http = NewHTTPListener(m.sessions, m.tasks, m.profile)
	return m.http.StartTLS(port, certFile, keyFile)
}

// Stop arrête tous les listeners
func (m *Manager) Stop() {
	if m.http != nil {
		m.http.Stop()
	}
}

// GetProfile retourne le profil actif
func (m *Manager) GetProfile() *profile.Profile {
	return m.profile
}

// SetProfile change le profil actif
func (m *Manager) SetProfile(prof *profile.Profile) {
	m.profile = prof
}
