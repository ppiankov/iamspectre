package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WO-44@v2: generated configuration must expose the AWS service-linked role control.
func TestSampleConfigIncludesServiceLinkedRoleOption(t *testing.T) {
	if !strings.Contains(sampleConfig, "include_service_linked_roles: false") {
		t.Fatal("sample config omits include_service_linked_roles")
	}
}

// WO-98@v1: pin first-run generation, no-force preservation, and explicit force overwrite.
func TestRunInitGeneratesAndPreservesFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	previousForce := initFlags.force
	t.Cleanup(func() { initFlags.force = previousForce })

	initFlags.force = false
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("first run: %v", err)
	}

	wantFiles := map[string]string{
		".iamspectre.yaml":                  sampleConfig,
		"iamspectre-aws-policy.json":        sampleAWSIAMPolicy,
		"iamspectre-azure-permissions.json": sampleAzureGraphPermissions,
	}
	for path, want := range wantFiles {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != want {
			t.Fatalf("%s content differs from embedded sample", path)
		}
	}

	const operatorConfig = "operator-owned-config\n"
	if err := os.WriteFile(".iamspectre.yaml", []byte(operatorConfig), 0o644); err != nil {
		t.Fatalf("replace config fixture: %v", err)
	}
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("no-force run: %v", err)
	}
	assertFileContent(t, ".iamspectre.yaml", operatorConfig)

	initFlags.force = true
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("force run: %v", err)
	}
	assertFileContent(t, ".iamspectre.yaml", sampleConfig)
}

// WO-98@v1: create nested output paths without depending on the process working directory.
func TestWriteIfNotExistsCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "sample.txt")
	if err := writeIfNotExists(path, "sample", false); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	assertFileContent(t, path, "sample")
}

// WO-98@v1: return stable filesystem failures without altering the blocking operator file.
func TestWriteIfNotExistsReturnsFilesystemErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("preserve"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	err := writeIfNotExists(filepath.Join(blocker, "child"), "sample", true)
	if err == nil || !strings.Contains(err.Error(), "create directory") {
		t.Fatalf("nested write error = %v, want create directory context", err)
	}
	assertFileContent(t, blocker, "preserve")

	targetDir := filepath.Join(dir, "target")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatalf("create target directory: %v", err)
	}
	if err := writeIfNotExists(targetDir, "sample", true); err == nil {
		t.Fatal("force-writing a directory should fail")
	}
}

// WO-98@v1: stop generation at each ordered write failure instead of claiming a complete bundle.
func TestRunInitReturnsEachOutputFailure(t *testing.T) {
	paths := []string{
		".iamspectre.yaml",
		"iamspectre-aws-policy.json",
		"iamspectre-azure-permissions.json",
	}

	for _, blockedPath := range paths {
		t.Run(blockedPath, func(t *testing.T) {
			t.Chdir(t.TempDir())
			previousForce := initFlags.force
			t.Cleanup(func() { initFlags.force = previousForce })
			initFlags.force = true

			if err := os.Mkdir(blockedPath, 0o755); err != nil {
				t.Fatalf("create blocking directory: %v", err)
			}
			if err := runInit(nil, nil); err == nil {
				t.Fatalf("runInit should fail when %s is a directory", blockedPath)
			}
		})
	}
}

// WO-98@v1: centralize exact file assertions for test-owned paths.
func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}
