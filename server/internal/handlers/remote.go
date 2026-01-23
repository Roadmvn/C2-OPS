package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveDesktopFrame sauvegarde une capture d'écran du bureau distant
func SaveDesktopFrame(agentID string, data []byte) (string, error) {
	// Crée le dossier si nécessaire
	dir := filepath.Join("downloads", "desktop", agentID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("échec création dossier: %v", err)
	}

	// Génère le nom de fichier avec timestamp
	filename := fmt.Sprintf("frame_%s.jpg", time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, filename)

	// Écrit les données sur le disque
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", fmt.Errorf("échec écriture fichier: %v", err)
	}

	return path, nil
}
