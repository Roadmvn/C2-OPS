/*
 * main.go - Point d'entrée du Teamserver Ghost
 *
 * Lance les listeners, l'API REST et la console CLI.
 */
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ghost-server/internal/api"
	"ghost-server/internal/cli"
	"ghost-server/internal/listener"
	"ghost-server/internal/profile"
	"ghost-server/internal/session"
	"ghost-server/internal/task"
)

// Configuration du serveur
type Config struct {
	APIPort      int
	ListenerPort int
	ProfilePath  string
	UseTLS       bool
	CertFile     string
	KeyFile      string
}

func main() {
	// Parse les arguments
	config := Config{}
	flag.IntVar(&config.APIPort, "api-port", 3000, "Port for the API/Web interface")
	flag.IntVar(&config.ListenerPort, "listener-port", 443, "Port for agent callbacks")
	flag.StringVar(&config.ProfilePath, "profile", "profiles/default.yaml", "Path to malleable profile")
	flag.BoolVar(&config.UseTLS, "tls", false, "Enable TLS for listener")
	flag.StringVar(&config.CertFile, "cert", "certs/server.crt", "TLS certificate file")
	flag.StringVar(&config.KeyFile, "key", "certs/server.key", "TLS key file")
	flag.Parse()

	// Banner
	printBanner()

	// Initialisation des composants
	log.Println("[*] Initializing Ghost C2 Server...")

	// Charge le profil malleable
	prof, err := profile.LoadFromFile(config.ProfilePath)
	if err != nil {
		log.Printf("[!] Failed to load profile: %v, using default", err)
		prof = profile.GetDefault()
	}
	log.Printf("[+] Loaded profile: %s", prof.Name)

	// Initialise le gestionnaire de sessions
	sessionMgr := session.NewManager()
	log.Println("[+] Session manager initialized")

	// Initialise la queue de tâches
	taskQueue := task.NewQueue()
	log.Println("[+] Task queue initialized")

	// Démarre le listener HTTP pour les agents
	listenerMgr := listener.NewManager(sessionMgr, taskQueue, prof)
	go func() {
		if config.UseTLS {
			err := listenerMgr.StartHTTPS(config.ListenerPort, config.CertFile, config.KeyFile)
			if err != nil {
				log.Fatalf("[-] Failed to start HTTPS listener: %v", err)
			}
		} else {
			err := listenerMgr.StartHTTP(config.ListenerPort)
			if err != nil {
				log.Fatalf("[-] Failed to start HTTP listener: %v", err)
			}
		}
	}()
	log.Printf("[+] Agent listener started on port %d", config.ListenerPort)

	// Démarre l'API REST + WebSocket
	apiServer := api.NewServer(sessionMgr, taskQueue, listenerMgr)
	go func() {
		err := apiServer.Start(config.APIPort)
		if err != nil {
			log.Fatalf("[-] Failed to start API server: %v", err)
		}
	}()
	log.Printf("[+] API/Web server started on http://localhost:%d", config.APIPort)

	// Démarre la console CLI en mode interactif
	console := cli.NewConsole(sessionMgr, taskQueue, listenerMgr)
	go console.Run()

	// Attend le signal d'arrêt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("[+] Ghost C2 Server is ready!")
	log.Println("[*] Type 'help' in the console for available commands")

	<-sigChan

	log.Println("\n[*] Shutting down...")
	listenerMgr.Stop()
	apiServer.Stop()
	log.Println("[+] Goodbye!")
}

func printBanner() {
	banner := `
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
                                    C2 Framework
                                    v1.0.0
`
	fmt.Println(banner)
}
