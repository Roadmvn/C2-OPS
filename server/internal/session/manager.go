/*
 * manager.go - Gestionnaire de sessions agents
 */
package session

import (
	"sync"

	"ghost-server/pkg/protocol"
)

// Manager gère les sessions des agents
type Manager struct {
	mu     sync.RWMutex
	agents map[string]*Agent
}

// NewManager crée un nouveau gestionnaire de sessions
func NewManager() *Manager {
	return &Manager{
		agents: make(map[string]*Agent),
	}
}

// Register enregistre un nouvel agent ou met à jour un existant
func (m *Manager) Register(id string, data *protocol.CheckinData) *Agent {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check si l'agent existe déjà
	if existing, ok := m.agents[id]; ok {
		existing.UpdateLastSeen()
		return existing
	}

	// Crée un nouvel agent
	agent := NewAgent(id, data)
	m.agents[id] = agent

	return agent
}

// Get récupère un agent par son ID
func (m *Manager) Get(id string) (*Agent, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agent, ok := m.agents[id]
	return agent, ok
}

// GetAll retourne tous les agents
func (m *Manager) GetAll() []*Agent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agents := make([]*Agent, 0, len(m.agents))
	for _, agent := range m.agents {
		agents = append(agents, agent)
	}
	return agents
}

// Remove supprime un agent
func (m *Manager) Remove(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.agents[id]; ok {
		delete(m.agents, id)
		return true
	}
	return false
}

// UpdateLastSeen met à jour le dernier contact d'un agent
func (m *Manager) UpdateLastSeen(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if agent, ok := m.agents[id]; ok {
		agent.UpdateLastSeen()
		return true
	}
	return false
}

// Count retourne le nombre d'agents
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.agents)
}

// CountByStatus retourne le nombre d'agents par statut
func (m *Manager) CountByStatus() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	counts := map[string]int{
		"active":   0,
		"inactive": 0,
		"dead":     0,
	}

	for _, agent := range m.agents {
		counts[agent.GetStatus()]++
	}

	return counts
}
