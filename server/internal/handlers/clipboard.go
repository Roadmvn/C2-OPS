package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveClipboard sauvegarde le dump du presse-papier sur le disque
func SaveClipboard(agentID string, data string) (string, error) {
	// S'assure que le dossier existe
	dir := filepath.Join("downloads", "clipboard", agentID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %v", err)
	}

	// Génère le nom de fichier
	filename := fmt.Sprintf("clipboard_%s.txt", time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, filename)

	// Écrit dans le fichier
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	return path, nil
}
