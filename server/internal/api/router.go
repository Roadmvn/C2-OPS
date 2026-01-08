/*
 * router.go - API REST pour l'interface web
 */
package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"ghost-server/internal/listener"
	"ghost-server/internal/session"
	"ghost-server/internal/task"
	"ghost-server/pkg/protocol"
)

// Server représente le serveur API
type Server struct {
	sessions *session.Manager
	tasks    *task.Queue
	listener *listener.Manager
	router   *gin.Engine
	server   *http.Server
}

// NewServer crée un nouveau serveur API
func NewServer(sessions *session.Manager, tasks *task.Queue, listeners *listener.Manager) *Server {
	gin.SetMode(gin.ReleaseMode)

	s := &Server{
		sessions: sessions,
		tasks:    tasks,
		listener: listeners,
		router:   gin.New(),
	}

	s.setupRoutes()
	return s
}

// setupRoutes configure les routes de l'API
func (s *Server) setupRoutes() {
	// Middleware
	s.router.Use(gin.Recovery())
	s.router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Sert les fichiers statiques du frontend
	s.router.Static("/assets", "./web/dist/assets")
	s.router.StaticFile("/", "./web/dist/index.html")
	s.router.NoRoute(func(c *gin.Context) {
		c.File("./web/dist/index.html")
	})

	// API Routes
	api := s.router.Group("/api")
	{
		// Dashboard
		api.GET("/stats", s.getStats)

		// Agents
		api.GET("/agents", s.getAgents)
		api.GET("/agents/:id", s.getAgent)
		api.DELETE("/agents/:id", s.deleteAgent)
		api.POST("/agents/:id/task", s.createTask)
		api.GET("/agents/:id/tasks", s.getAgentTasks)

		// Tasks
		api.GET("/tasks", s.getAllTasks)
		api.GET("/tasks/:id", s.getTask)
	}
}

// Start démarre le serveur API
func (s *Server) Start(port int) error {
	s.server = &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: s.router,
	}
	return s.server.ListenAndServe()
}

// Stop arrête le serveur API
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// ============================================================================
// Handlers
// ============================================================================

// getStats retourne les statistiques du dashboard
func (s *Server) getStats(c *gin.Context) {
	counts := s.sessions.CountByStatus()

	c.JSON(http.StatusOK, gin.H{
		"total_agents":    s.sessions.Count(),
		"active_agents":   counts["active"],
		"inactive_agents": counts["inactive"],
		"dead_agents":     counts["dead"],
		"total_tasks":     s.tasks.Count(),
	})
}

// getAgents retourne la liste des agents
func (s *Server) getAgents(c *gin.Context) {
	agents := s.sessions.GetAll()
	result := make([]*protocol.Agent, len(agents))

	for i, agent := range agents {
		result[i] = agent.ToProtocol()
	}

	c.JSON(http.StatusOK, result)
}

// getAgent retourne un agent spécifique
func (s *Server) getAgent(c *gin.Context) {
	id := c.Param("id")

	agent, ok := s.sessions.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}

	c.JSON(http.StatusOK, agent.ToProtocol())
}

// deleteAgent supprime un agent
func (s *Server) deleteAgent(c *gin.Context) {
	id := c.Param("id")

	if s.sessions.Remove(id) {
		c.JSON(http.StatusOK, gin.H{"message": "Agent removed"})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
	}
}

// CreateTaskRequest structure pour créer une tâche
type CreateTaskRequest struct {
	Command string `json:"command" binding:"required"`
	Args    string `json:"args"`
}

// createTask crée une nouvelle tâche pour un agent
func (s *Server) createTask(c *gin.Context) {
	agentID := c.Param("id")

	// Vérifie que l'agent existe
	if _, ok := s.sessions.Get(agentID); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}

	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Ajoute la tâche
	qt := s.tasks.Add(agentID, req.Command, req.Args)

	c.JSON(http.StatusCreated, gin.H{
		"task_id": qt.Task.TaskID,
		"message": "Task queued",
	})
}

// getAgentTasks retourne les tâches d'un agent
func (s *Server) getAgentTasks(c *gin.Context) {
	agentID := c.Param("id")

	tasks := s.tasks.GetForAgent(agentID)

	result := make([]gin.H, len(tasks))
	for i, qt := range tasks {
		item := gin.H{
			"task_id":    qt.Task.TaskID,
			"command":    qt.Task.Command,
			"args":       qt.Task.Args,
			"created_at": qt.CreatedAt,
			"picked":     qt.Picked,
			"completed":  qt.Completed,
		}
		if qt.Result != nil {
			item["result"] = gin.H{
				"status": qt.Result.Status,
				"output": qt.Result.Output,
			}
		}
		result[i] = item
	}

	c.JSON(http.StatusOK, result)
}

// getAllTasks retourne toutes les tâches
func (s *Server) getAllTasks(c *gin.Context) {
	// Pour l'instant, on retourne juste le count
	c.JSON(http.StatusOK, gin.H{
		"count": s.tasks.Count(),
	})
}

// getTask retourne une tâche spécifique
func (s *Server) getTask(c *gin.Context) {
	taskID := c.Param("id")

	qt, ok := s.tasks.GetByID(taskID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	result := gin.H{
		"task_id":    qt.Task.TaskID,
		"agent_id":   qt.AgentID,
		"command":    qt.Task.Command,
		"args":       qt.Task.Args,
		"created_at": qt.CreatedAt,
		"picked":     qt.Picked,
		"completed":  qt.Completed,
	}

	if qt.Result != nil {
		result["result"] = gin.H{
			"status": qt.Result.Status,
			"output": qt.Result.Output,
		}
	}

	c.JSON(http.StatusOK, result)
}
