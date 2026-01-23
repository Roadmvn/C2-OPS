package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveAudio saves an audio recording (WAV) to disk
func SaveAudio(agentID string, data []byte) (string, error) {
	// Ensure directory exists
	dir := filepath.Join("downloads", "audio", agentID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %v", err)
	}

	// Generate filename with timestamp
	filename := fmt.Sprintf("mic_%s.wav", time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, filename)

	// Write data to disk
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	return path, nil
}
