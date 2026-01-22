package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveScreenshot saves the screenshot data to disk
func SaveScreenshot(agentID string, data []byte) (string, error) {
	// Ensure directory exists
	// structure: downloads/screenshots/<agent_id>/
	dir := filepath.Join("downloads", "screenshots", agentID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %v", err)
	}

	// Generate filename
	filename := fmt.Sprintf("screenshot_%s.bmp", time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, filename)

	// Write file (using os.WriteFile for atomic write)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	return path, nil
}
