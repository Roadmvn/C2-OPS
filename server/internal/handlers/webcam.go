package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveWebcam sauvegarde une capture webcam sur le disque
func SaveWebcam(agentID string, data []byte) (string, error) {
	// S'assure que le dossier existe
	dir := filepath.Join("downloads", "webcam", agentID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("échec création dossier: %v", err)
	}

	// Génère le nom de fichier avec timestamp
	filename := fmt.Sprintf("webcam_%s.bmp", time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, filename)

	// Écrit les données sur le disque
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", fmt.Errorf("échec écriture fichier: %v", err)
	}

	return path, nil
}
