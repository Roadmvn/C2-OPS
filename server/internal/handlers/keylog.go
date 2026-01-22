package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveKeylog saves keylogger data to disk
func SaveKeylog(agentID string, data string) (string, error) {
	// Ensure directory exists
	dir := filepath.Join("downloads", "keylogs", agentID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %v", err)
	}

	// Generate filename
	filename := fmt.Sprintf("keylog_%s.txt", time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, filename)

	// Append to file (or create new)
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	return path, nil
}
