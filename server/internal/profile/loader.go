/*
 * loader.go - Chargement des profils malléables
 */
package profile

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Profile représente un profil malleable C2
type Profile struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	HTTP        HTTPConfig   `yaml:"http"`
	Timing      TimingConfig `yaml:"timing"`
	SSL         SSLConfig    `yaml:"ssl,omitempty"`
}

// HTTPConfig configuration HTTP du profil
type HTTPConfig struct {
	UserAgent string            `yaml:"user_agent"`
	Headers   map[string]string `yaml:"headers"`
	Get       EndpointConfig    `yaml:"get"`
	Post      EndpointConfig    `yaml:"post"`
}

// EndpointConfig configuration d'un endpoint
type EndpointConfig struct {
	URIs      []string          `yaml:"uri"`
	Headers   map[string]string `yaml:"headers,omitempty"`
	Transform TransformConfig   `yaml:"transform,omitempty"`
}

// TransformConfig configuration des transformations de données
type TransformConfig struct {
	Encode  string `yaml:"encode,omitempty"`  // base64, hex, etc.
	Prepend string `yaml:"prepend,omitempty"` // Données à ajouter avant
	Append  string `yaml:"append,omitempty"`  // Données à ajouter après
	Wrapper string `yaml:"wrapper,omitempty"` // Template avec %%DATA%%
}

// TimingConfig configuration du timing
type TimingConfig struct {
	Sleep    int `yaml:"sleep"`     // Secondes entre les callbacks
	Jitter   int `yaml:"jitter"`    // Pourcentage de jitter
	MaxRetry int `yaml:"max_retry"` // Nombre max de retries
}

// SSLConfig configuration SSL/TLS
type SSLConfig struct {
	Certificate string `yaml:"certificate,omitempty"`
	Verify      bool   `yaml:"verify"`
}

// LoadFromFile charge un profil depuis un fichier YAML
func LoadFromFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var profile Profile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

// GetDefault retourne le profil par défaut
func GetDefault() *Profile {
	return &Profile{
		Name:        "default",
		Description: "Default minimal profile",
		HTTP: HTTPConfig{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			Headers: map[string]string{
				"Accept":          "*/*",
				"Accept-Language": "en-US,en;q=0.9",
			},
			Get: EndpointConfig{
				URIs: []string{"/api/get", "/check", "/status"},
			},
			Post: EndpointConfig{
				URIs: []string{"/api/post", "/update", "/submit"},
			},
		},
		Timing: TimingConfig{
			Sleep:    60,
			Jitter:   20,
			MaxRetry: 3,
		},
		SSL: SSLConfig{
			Verify: false,
		},
	}
}
