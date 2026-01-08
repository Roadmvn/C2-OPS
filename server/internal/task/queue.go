/*
 * queue.go - File d'attente des tâches
 */
package task

import (
	"sync"
	"time"

	"ghost-server/pkg/protocol"

	"github.com/google/uuid"
)

// QueuedTask représente une tâche en attente
type QueuedTask struct {
	Task      protocol.Task
	AgentID   string
	CreatedAt time.Time
	Picked    bool
	Result    *protocol.TaskResult
	Completed bool
}

// Queue gère la file d'attente des tâches par agent
type Queue struct {
	mu    sync.RWMutex
	tasks map[string][]*QueuedTask // agent_id -> tasks
	all   map[string]*QueuedTask   // task_id -> task
}

// NewQueue crée une nouvelle file de tâches
func NewQueue() *Queue {
	return &Queue{
		tasks: make(map[string][]*QueuedTask),
		all:   make(map[string]*QueuedTask),
	}
}

// Add ajoute une tâche à la queue d'un agent
func (q *Queue) Add(agentID, command, args string) *QueuedTask {
	q.mu.Lock()
	defer q.mu.Unlock()

	taskID := uuid.New().String()

	qt := &QueuedTask{
		Task: protocol.Task{
			TaskID:  taskID,
			Command: command,
			Args:    args,
		},
		AgentID:   agentID,
		CreatedAt: time.Now(),
		Picked:    false,
		Completed: false,
	}

	q.tasks[agentID] = append(q.tasks[agentID], qt)
	q.all[taskID] = qt

	return qt
}

// GetPending récupère les tâches en attente pour un agent
func (q *Queue) GetPending(agentID string) []protocol.Task {
	q.mu.Lock()
	defer q.mu.Unlock()

	var pending []protocol.Task

	for _, qt := range q.tasks[agentID] {
		if !qt.Picked {
			pending = append(pending, qt.Task)
			qt.Picked = true
		}
	}

	return pending
}

// SetResult enregistre le résultat d'une tâche
func (q *Queue) SetResult(taskID string, result *protocol.TaskResult) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if qt, ok := q.all[taskID]; ok {
		qt.Result = result
		qt.Completed = true
		return true
	}
	return false
}

// GetByID récupère une tâche par son ID
func (q *Queue) GetByID(taskID string) (*QueuedTask, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	qt, ok := q.all[taskID]
	return qt, ok
}

// GetForAgent récupère toutes les tâches d'un agent
func (q *Queue) GetForAgent(agentID string) []*QueuedTask {
	q.mu.RLock()
	defer q.mu.RUnlock()

	tasks := q.tasks[agentID]
	result := make([]*QueuedTask, len(tasks))
	copy(result, tasks)
	return result
}

// Count retourne le nombre de tâches
func (q *Queue) Count() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.all)
}

// Cleanup supprime les tâches complétées plus anciennes qu'une durée
func (q *Queue) Cleanup(maxAge time.Duration) int {
	q.mu.Lock()
	defer q.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for agentID, tasks := range q.tasks {
		var kept []*QueuedTask
		for _, qt := range tasks {
			if qt.Completed && qt.CreatedAt.Before(cutoff) {
				delete(q.all, qt.Task.TaskID)
				removed++
			} else {
				kept = append(kept, qt)
			}
		}
		q.tasks[agentID] = kept
	}

	return removed
}
