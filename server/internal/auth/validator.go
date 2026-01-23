package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Clé de build par défaut (sera générée à chaque nouvelle compilation)
// Dans un vrai déploiement, cette clé serait générée par le builder
var DefaultBuildKey = []byte("GhostC2-DefaultBuildKey-2026")

// Agent représente un agent authentifié
type AuthenticatedAgent struct {
	AgentID     string
	BuildKey    []byte
	LastSeen    time.Time
	IsRevoked   bool
	AuthToken   string
}

// Validator gère l'authentification des agents
type Validator struct {
	mu           sync.RWMutex
	buildKey     []byte
	agents       map[string]*AuthenticatedAgent
	challenges   map[string][]byte // agentID -> challenge en attente
	revokedList  map[string]bool   // agents révoqués
}

// NewValidator crée un nouveau validateur avec la clé de build
func NewValidator(buildKey []byte) *Validator {
	if len(buildKey) == 0 {
		buildKey = DefaultBuildKey
	}
	return &Validator{
		buildKey:    buildKey,
		agents:      make(map[string]*AuthenticatedAgent),
		challenges:  make(map[string][]byte),
		revokedList: make(map[string]bool),
	}
}

// GenerateChallenge génère un challenge pour un agent
func (v *Validator) GenerateChallenge(agentID string) (string, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return "", fmt.Errorf("échec génération challenge: %v", err)
	}

	v.mu.Lock()
	v.challenges[agentID] = challenge
	v.mu.Unlock()

	return hex.EncodeToString(challenge), nil
}

// ValidateResponse valide la réponse HMAC d'un agent au challenge
func (v *Validator) ValidateResponse(agentID string, responseHex string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Vérifie si l'agent est révoqué
	if v.revokedList[agentID] {
		return false, fmt.Errorf("agent révoqué")
	}

	// Récupère le challenge
	challenge, exists := v.challenges[agentID]
	if !exists {
		return false, fmt.Errorf("pas de challenge en attente pour cet agent")
	}

	// Calcule le HMAC attendu: HMAC-SHA256(buildKey, challenge)
	mac := hmac.New(sha256.New, v.buildKey)
	mac.Write(challenge)
	expectedMAC := mac.Sum(nil)

	// Décode la réponse
	response, err := hex.DecodeString(responseHex)
	if err != nil {
		return false, fmt.Errorf("réponse invalide: %v", err)
	}

	// Compare de manière sécurisée (constant-time)
	if !hmac.Equal(response, expectedMAC) {
		return false, nil
	}

	// Authentification réussie, enregistre l'agent
	delete(v.challenges, agentID)
	
	// Génère un token de session
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	authToken := hex.EncodeToString(tokenBytes)

	v.agents[agentID] = &AuthenticatedAgent{
		AgentID:   agentID,
		BuildKey:  v.buildKey,
		LastSeen:  time.Now(),
		IsRevoked: false,
		AuthToken: authToken,
	}

	return true, nil
}

// IsAuthenticated vérifie si un agent est authentifié
func (v *Validator) IsAuthenticated(agentID string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	agent, exists := v.agents[agentID]
	if !exists {
		return false
	}
	return !agent.IsRevoked
}

// ValidateToken vérifie le token d'un agent authentifié
func (v *Validator) ValidateToken(agentID, token string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	agent, exists := v.agents[agentID]
	if !exists || agent.IsRevoked {
		return false
	}
	
	return agent.AuthToken == token
}

// RevokeAgent révoque un agent (kill switch)
func (v *Validator) RevokeAgent(agentID string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.revokedList[agentID] = true
	if agent, exists := v.agents[agentID]; exists {
		agent.IsRevoked = true
	}
}

// UpdateLastSeen met à jour le timestamp de dernière activité
func (v *Validator) UpdateLastSeen(agentID string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if agent, exists := v.agents[agentID]; exists {
		agent.LastSeen = time.Now()
	}
}

// GetAuthToken retourne le token d'authentification d'un agent
func (v *Validator) GetAuthToken(agentID string) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if agent, exists := v.agents[agentID]; exists {
		return agent.AuthToken
	}
	return ""
}

// ListAgents retourne la liste des agents authentifiés
func (v *Validator) ListAgents() []AuthenticatedAgent {
	v.mu.RLock()
	defer v.mu.RUnlock()

	result := make([]AuthenticatedAgent, 0, len(v.agents))
	for _, agent := range v.agents {
		result = append(result, *agent)
	}
	return result
}
