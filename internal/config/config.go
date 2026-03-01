package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds iamspectre configuration loaded from .iamspectre.yaml.
type Config struct {
	Profile     string   `yaml:"profile"`
	Project     string   `yaml:"project"`
	TenantID    string   `yaml:"tenant_id"`
	StaleDays   int      `yaml:"stale_days"`
	SeverityMin string   `yaml:"severity_min"`
	Format      string   `yaml:"format"`
	Timeout     string   `yaml:"timeout"`
	Exclude     Exclude  `yaml:"exclude"`
	Regions     []string `yaml:"regions"`
}

// Exclude defines resources to skip during scanning.
type Exclude struct {
	Principals  []string `yaml:"principals"`
	ResourceIDs []string `yaml:"resource_ids"`
}

// TimeoutDuration parses the timeout string as a duration.
func (c Config) TimeoutDuration() time.Duration {
	if c.Timeout == "" {
		return 0
	}
	d, _ := time.ParseDuration(c.Timeout)
	return d
}

// Load searches for .iamspectre.yaml or .iamspectre.yml in the given directory
// and returns the parsed config. Returns an empty Config if no file is found.
func Load(dir string) (Config, error) {
	candidates := []string{
		filepath.Join(dir, ".iamspectre.yaml"),
		filepath.Join(dir, ".iamspectre.yml"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}

		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %s: %w", path, err)
		}
		return cfg, nil
	}

	return Config{}, nil
}
