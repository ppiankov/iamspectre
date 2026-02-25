package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "" {
		t.Fatalf("expected empty profile, got %q", cfg.Profile)
	}
	if cfg.StaleDays != 0 {
		t.Fatalf("expected zero stale_days, got %d", cfg.StaleDays)
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	content := `profile: production
project: my-gcp-project
stale_days: 60
severity_min: medium
format: json
timeout: 5m
exclude:
  principals:
    - "arn:aws:iam::123456789012:user/admin"
  resource_ids:
    - "i-0abc123def456"
`
	if err := os.WriteFile(filepath.Join(dir, ".iamspectre.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "production" {
		t.Fatalf("expected profile production, got %q", cfg.Profile)
	}
	if cfg.Project != "my-gcp-project" {
		t.Fatalf("expected project my-gcp-project, got %q", cfg.Project)
	}
	if cfg.StaleDays != 60 {
		t.Fatalf("expected stale_days 60, got %d", cfg.StaleDays)
	}
	if cfg.SeverityMin != "medium" {
		t.Fatalf("expected severity_min medium, got %q", cfg.SeverityMin)
	}
	if cfg.Format != "json" {
		t.Fatalf("expected format json, got %q", cfg.Format)
	}
	if len(cfg.Exclude.Principals) != 1 {
		t.Fatalf("expected 1 excluded principal, got %d", len(cfg.Exclude.Principals))
	}
	if len(cfg.Exclude.ResourceIDs) != 1 {
		t.Fatalf("expected 1 excluded resource ID, got %d", len(cfg.Exclude.ResourceIDs))
	}
}

func TestLoad_YMLExtension(t *testing.T) {
	dir := t.TempDir()
	content := `profile: staging
stale_days: 30
`
	if err := os.WriteFile(filepath.Join(dir, ".iamspectre.yml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "staging" {
		t.Fatalf("expected profile staging, got %q", cfg.Profile)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	content := `[invalid yaml content`
	if err := os.WriteFile(filepath.Join(dir, ".iamspectre.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoad_YAMLPriority(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `profile: from-yaml`
	ymlContent := `profile: from-yml`
	if err := os.WriteFile(filepath.Join(dir, ".iamspectre.yaml"), []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".iamspectre.yml"), []byte(ymlContent), 0o644); err != nil {
		t.Fatalf("write yml: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "from-yaml" {
		t.Fatalf("expected profile from-yaml (priority), got %q", cfg.Profile)
	}
}

func TestConfig_TimeoutDuration(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
		wantSec float64
	}{
		{"empty", "", 0},
		{"5m", "5m", 300},
		{"30s", "30s", 30},
		{"invalid", "notaduration", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Timeout: tt.timeout}
			got := cfg.TimeoutDuration().Seconds()
			if got != tt.wantSec {
				t.Fatalf("expected %f seconds, got %f", tt.wantSec, got)
			}
		})
	}
}
