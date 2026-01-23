package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveCredentials sauvegarde les credentials extraites sur le disque
func SaveCredentials(agentID string, credType string, data string) (string, error) {
	// Crée le dossier si nécessaire
	dir := filepath.Join("downloads", "credentials", agentID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("échec création dossier: %v", err)
	}

	// Génère le nom de fichier avec timestamp
	filename := fmt.Sprintf("%s_%s.json", credType, time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, filename)

	// Écrit les données sur le disque
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		return "", fmt.Errorf("échec écriture fichier: %v", err)
	}

	return path, nil
}
