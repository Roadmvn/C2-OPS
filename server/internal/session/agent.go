/*
 * agent.go - Représentation d'un agent connecté
 */
package session

import (
	"sync"
	"time"

	"ghost-server/pkg/protocol"
)

// Agent représente un agent connecté au C2
type Agent struct {
	mu sync.RWMutex

	ID        string
	Hostname  string
	Username  string
	Domain    string
	OS        string
	Arch      string
	PID       int
	Elevated  bool
	FirstSeen time.Time
	LastSeen  time.Time
}

// NewAgent crée un nouvel agent à partir des données de check-in
func NewAgent(id string, data *protocol.CheckinData) *Agent {
	now := time.Now()
	return &Agent{
		ID:        id,
		Hostname:  data.Hostname,
		Username:  data.Username,
		Domain:    data.Domain,
		OS:        data.OS,
		Arch:      data.Arch,
		PID:       data.PID,
		Elevated:  data.Elevated,
		FirstSeen: now,
		LastSeen:  now,
	}
}

// UpdateLastSeen met à jour le timestamp de dernier contact
func (a *Agent) UpdateLastSeen() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.LastSeen = time.Now()
}

// GetStatus retourne le statut de l'agent basé sur le dernier contact
func (a *Agent) GetStatus() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	elapsed := time.Since(a.LastSeen)

	// Active: contact dans les dernières 2 minutes
	if elapsed < 2*time.Minute {
		return "active"
	}

	// Inactive: contact dans les dernières 10 minutes
	if elapsed < 10*time.Minute {
		return "inactive"
	}

	// Dead: pas de contact depuis plus de 10 minutes
	return "dead"
}

// ToProtocol convertit l'agent en structure du protocole
func (a *Agent) ToProtocol() *protocol.Agent {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return &protocol.Agent{
		ID:        a.ID,
		Hostname:  a.Hostname,
		Username:  a.Username,
		Domain:    a.Domain,
		OS:        a.OS,
		Arch:      a.Arch,
		PID:       a.PID,
		Elevated:  a.Elevated,
		FirstSeen: a.FirstSeen,
		LastSeen:  a.LastSeen,
		Status:    a.GetStatus(),
	}
}

// GetDisplayName retourne un nom d'affichage pour l'agent
func (a *Agent) GetDisplayName() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.Domain != "" {
		return a.Domain + "\\" + a.Username + "@" + a.Hostname
	}
	return a.Username + "@" + a.Hostname
}
