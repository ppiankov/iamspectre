package commands

import (
	"os"
	"strings"
	"testing"
)

// WO-6@v2: keep public provider examples aligned with the registered Cobra subcommands.
func TestREADMEProviderCommands(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	content := string(readme)
	if strings.Contains(content, "scan --provider") {
		t.Fatal("README documents the nonexistent scan --provider command")
	}

	required := []string{
		`.\iamspectre.exe aws --format json`,
		`iamspectre aws --format json`,
		"| `iamspectre aws` |",
		"| `iamspectre gcp` |",
		"| `iamspectre azure` |",
	}
	for _, fragment := range required {
		if !strings.Contains(content, fragment) {
			t.Errorf("README omits registered command contract %q", fragment)
		}
	}
}
