package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// WO-133@v2: enforce release/changelog/dispatch contract from parsed workflow contracts.
func TestReleaseWorkflowDispatchShape(t *testing.T) {
	release := readWorkflow(t, ".github/workflows/release.yml")
	on, ok := release["on"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing on")
	}

	push, ok := on["push"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing push trigger")
	}
	tags, ok := push["tags"].([]any)
	if !ok || len(tags) == 0 {
		t.Fatalf("release.yml missing tags trigger")
	}
	if tags[0] != "v*" {
		t.Fatalf("release.yml tags trigger = %v, want v*", tags[0])
	}

	dispatch, ok := on["workflow_dispatch"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing workflow_dispatch trigger")
	}
	inputs, ok := dispatch["inputs"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing workflow_dispatch inputs")
	}
	tagInput, ok := inputs["tag"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing workflow_dispatch input tag")
	}
	if tagInput["required"] != true {
		t.Fatalf("release.yml tag input required = %v, want true", tagInput["required"])
	}

	concurrency, ok := release["concurrency"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing concurrency block")
	}
	group, ok := concurrency["group"].(string)
	if !ok {
		t.Fatalf("release.yml concurrency.group missing")
	}
	if group != "release-${{ github.event_name == 'workflow_dispatch' && inputs.tag || github.ref_name }}" {
		t.Fatalf("release.yml concurrency group = %q, want normalized tag group", group)
	}
	if cancelInProgress, ok := concurrency["cancel-in-progress"].(bool); !ok || cancelInProgress {
		t.Fatalf("release.yml concurrency cancel-in-progress = %v, want false", cancelInProgress)
	}

	releaseJobs, ok := release["jobs"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing jobs block")
	}
	releaseJob, ok := releaseJobs["release"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing release job")
	}
	releaseSteps, ok := releaseJob["steps"].([]any)
	if !ok {
		t.Fatalf("release.yml release job missing steps")
	}
	validateJob, ok := releaseJobs["validate-changelog"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing validate-changelog job")
	}
	validateSteps, ok := validateJob["steps"].([]any)
	if !ok {
		t.Fatalf("release.yml validate-changelog job missing steps")
	}

	changelogIndex := -1
	for index, stepValue := range validateSteps {
		step, ok := stepValue.(map[string]any)
		if !ok {
			continue
		}
		name, _ := step["name"].(string)
		run, _ := step["run"].(string)
		if strings.Contains(strings.ToLower(name), "changelog") || strings.Contains(run, "CHANGELOG.md") {
			changelogIndex = index
		}
	}
	if changelogIndex == -1 {
		t.Fatalf("release.yml missing changelog validation step")
	}

	goreleaserIndex := -1
	for index, stepValue := range releaseSteps {
		step, ok := stepValue.(map[string]any)
		if !ok {
			continue
		}
		run, _ := step["run"].(string)
		if strings.Contains(run, "goreleaser release --clean") {
			goreleaserIndex = index
		}
	}
	if goreleaserIndex == -1 {
		t.Fatalf("release.yml missing goreleaser release step")
	}
	if _, hasNeeds := releaseJob["needs"]; !hasNeeds {
		t.Fatalf("release.yml release job missing needs")
	}
	needs, ok := releaseJob["needs"].([]any)
	if !ok {
		t.Fatalf("release.yml release job needs shape = %T, want array", releaseJob["needs"])
	}
	validateDep := false
	for _, need := range needs {
		if need == "validate-changelog" {
			validateDep = true
		}
	}
	if !validateDep {
		t.Fatalf("release.yml release job must depend on validate-changelog")
	}
}

// WO-133@v2: single dispatch path in CI must be explicit and built-in-token based.
func TestCIWorkflowReleaseDispatchShape(t *testing.T) {
	ci := sourceWorkflow(t, ".github/workflows/ci.yml")
	if occurrences(ci, "gh workflow run release.yml") != 1 {
		t.Fatalf("ci.yml expected exactly one release dispatch command, got %d", occurrences(ci, "gh workflow run release.yml"))
	}
	if !strings.Contains(ci, "GH_TOKEN: ${{ github.token }}") {
		t.Fatalf("ci.yml expected built-in github.token for dispatch")
	}
	if !strings.Contains(ci, "if: steps.tag.outputs.pushed == 'true'") {
		t.Fatalf("ci.yml expected tag push guard on dispatch step")
	}

	ciWorkflow := readWorkflow(t, ".github/workflows/ci.yml")
	jobs, ok := ciWorkflow["jobs"].(map[string]any)
	if !ok {
		t.Fatalf("ci.yml missing jobs block")
	}
	autoTag, ok := jobs["auto-tag"].(map[string]any)
	if !ok {
		t.Fatalf("ci.yml missing auto-tag job")
	}
	if autoTag["if"] != "github.event_name == 'push' && github.ref == 'refs/heads/main'" {
		t.Fatalf("ci.yml auto-tag if condition = %v, want push+main-only", autoTag["if"])
	}
}

// WO-96: assert archives are still declared before checksums in GoReleaser
// config, and that the deprecated `brews` publisher has not crept back in —
// Homebrew Formula publishing is a separate, explicit-version step outside
// GoReleaser now (see TestReleaseWorkflowHomebrewPublishSequencing).
func TestReleaseGoreleaserSectionOrder(t *testing.T) {
	config := sourceWorkflow(t, ".goreleaser.yml")
	archivesIndex := strings.Index(config, "archives:")
	if archivesIndex == -1 {
		t.Fatalf(".goreleaser.yml missing archives block")
	}
	checksumIndex := strings.Index(config, "checksum:")
	if checksumIndex == -1 {
		t.Fatalf(".goreleaser.yml missing checksum block")
	}
	if archivesIndex >= checksumIndex {
		t.Fatalf(".goreleaser.yml expected archives before checksum, got indices %d/%d", archivesIndex, checksumIndex)
	}
	if strings.Contains(config, "brews:") {
		t.Fatalf(".goreleaser.yml still declares the deprecated brews publisher; use cmd/publish-homebrew-formula instead")
	}
	if strings.Contains(config, "dockers:") || strings.Contains(config, "docker_manifests:") {
		t.Fatalf(".goreleaser.yml still declares deprecated dockers/docker_manifests; use dockers_v2 instead")
	}
	if !strings.Contains(config, "dockers_v2:") {
		t.Fatalf(".goreleaser.yml missing dockers_v2 block")
	}
}

// WO-96: the Homebrew Formula tap update must run after GoReleaser has
// produced checksums.txt, and must fail the job (not just log a warning) if
// the release credential is missing.
func TestReleaseWorkflowHomebrewPublishSequencing(t *testing.T) {
	release := readWorkflow(t, ".github/workflows/release.yml")
	releaseJobs, ok := release["jobs"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing jobs block")
	}
	releaseJob, ok := releaseJobs["release"].(map[string]any)
	if !ok {
		t.Fatalf("release.yml missing release job")
	}
	steps, ok := releaseJob["steps"].([]any)
	if !ok {
		t.Fatalf("release.yml release job missing steps")
	}

	goreleaserIndex, publishIndex := -1, -1
	var publishRun string
	for index, stepValue := range steps {
		step, ok := stepValue.(map[string]any)
		if !ok {
			continue
		}
		run, _ := step["run"].(string)
		if strings.Contains(run, "goreleaser release --clean") {
			goreleaserIndex = index
		}
		if strings.Contains(run, "cmd/publish-homebrew-formula") {
			publishIndex = index
			publishRun = run
		}
	}
	if goreleaserIndex == -1 {
		t.Fatalf("release.yml missing goreleaser release step")
	}
	if publishIndex == -1 {
		t.Fatalf("release.yml missing Homebrew formula publish step")
	}
	if publishIndex <= goreleaserIndex {
		t.Fatalf("release.yml Homebrew publish step (index %d) must run after the goreleaser release step (index %d)", publishIndex, goreleaserIndex)
	}
	if !strings.Contains(publishRun, "HOMEBREW_TAP_TOKEN") {
		t.Fatalf("release.yml Homebrew publish step must fail closed when HOMEBREW_TAP_TOKEN is missing")
	}
}

// WO-133@v2: read and decode workflow YAML once per test contract assertion.
func readWorkflow(t *testing.T, relativePath string) map[string]any {
	t.Helper()
	content := sourceWorkflow(t, relativePath)
	workflow := map[string]any{}
	if err := yaml.Unmarshal([]byte(content), &workflow); err != nil {
		t.Fatalf("unmarshal %s: %v", relativePath, err)
	}
	return workflow
}

// WO-133@v2: load workflow fixtures from repository root for contract checks.
func sourceWorkflow(t *testing.T, relativePath string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", relativePath))
	if err != nil {
		t.Fatalf("read %s: %v", relativePath, err)
	}
	return string(data)
}

// WO-133@v2: count literal matches for single-dispatch command assertions.
func occurrences(haystack, needle string) int {
	return strings.Count(haystack, needle)
}
