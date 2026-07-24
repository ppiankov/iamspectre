// Package release holds the release-engineering contracts and helpers that
// back .github/workflows/release.yml and .goreleaser.yml.
package release

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/template"
)

// FormulaInput describes the values needed to render an explicit-version
// Homebrew Formula. GoReleaser's built-in `brews` publisher was deprecated in
// favor of `homebrew_casks`, but this repository's packaging policy requires
// a Formula (not a Cask), so the formula is rendered and published directly
// (see cmd/publish-homebrew-formula) instead of through GoReleaser.
type FormulaInput struct {
	ProjectName string
	Version     string // semver without a leading "v"
	Homepage    string
	Description string
	License     string
	RepoOwner   string
	// Checksums maps an archive filename (as produced by the `archives`
	// name_template in .goreleaser.yml) to its sha256 from checksums.txt.
	Checksums map[string]string
}

// requiredArchive identifies one of the four platform/arch combinations the
// rendered Formula installs from.
type requiredArchive struct {
	goos, goarch string
}

var formulaArchives = []requiredArchive{
	{"darwin", "arm64"},
	{"darwin", "amd64"},
	{"linux", "arm64"},
	{"linux", "amd64"},
}

const formulaTemplate = `class {{.ClassName}} < Formula
  desc "{{.Description}}"
  homepage "{{.Homepage}}"
  version "{{.Version}}"
  license "{{.License}}"

  on_macos do
    on_arm do
      url "https://github.com/{{.RepoOwner}}/{{.ProjectName}}/releases/download/v{{.Version}}/{{.DarwinArm64File}}"
      sha256 "{{.DarwinArm64Sha}}"
    end
    on_intel do
      url "https://github.com/{{.RepoOwner}}/{{.ProjectName}}/releases/download/v{{.Version}}/{{.DarwinAmd64File}}"
      sha256 "{{.DarwinAmd64Sha}}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/{{.RepoOwner}}/{{.ProjectName}}/releases/download/v{{.Version}}/{{.LinuxArm64File}}"
      sha256 "{{.LinuxArm64Sha}}"
    end
    on_intel do
      url "https://github.com/{{.RepoOwner}}/{{.ProjectName}}/releases/download/v{{.Version}}/{{.LinuxAmd64File}}"
      sha256 "{{.LinuxAmd64Sha}}"
    end
  end

  def install
    bin.install "{{.ProjectName}}"
  end

  test do
    system "#{bin}/{{.ProjectName}}", "version"
  end
end
`

// RenderFormula renders an explicit-version Homebrew Formula for the four
// macOS/Linux amd64/arm64 archives. It fails closed: every archive must have
// a matching checksum, or no formula is produced.
func RenderFormula(in FormulaInput) (string, error) {
	archiveFile := func(goos, goarch string) string {
		return fmt.Sprintf("%s_%s_%s_%s.tar.gz", in.ProjectName, in.Version, goos, goarch)
	}

	shaFor := func(goos, goarch string) (string, error) {
		name := archiveFile(goos, goarch)
		sha, ok := in.Checksums[name]
		if !ok || sha == "" {
			return "", fmt.Errorf("missing checksum for %s", name)
		}
		return sha, nil
	}

	var missing []string
	shas := map[string]string{}
	for _, a := range formulaArchives {
		sha, err := shaFor(a.goos, a.goarch)
		if err != nil {
			missing = append(missing, err.Error())
			continue
		}
		shas[a.goos+"/"+a.goarch] = sha
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("cannot render Homebrew formula: %s", strings.Join(missing, "; "))
	}

	data := struct {
		ClassName string
		FormulaInput
		DarwinArm64File string
		DarwinArm64Sha  string
		DarwinAmd64File string
		DarwinAmd64Sha  string
		LinuxArm64File  string
		LinuxArm64Sha   string
		LinuxAmd64File  string
		LinuxAmd64Sha   string
	}{
		ClassName:       formulaClassName(in.ProjectName),
		FormulaInput:    in,
		DarwinArm64File: archiveFile("darwin", "arm64"),
		DarwinArm64Sha:  shas["darwin/arm64"],
		DarwinAmd64File: archiveFile("darwin", "amd64"),
		DarwinAmd64Sha:  shas["darwin/amd64"],
		LinuxArm64File:  archiveFile("linux", "arm64"),
		LinuxArm64Sha:   shas["linux/arm64"],
		LinuxAmd64File:  archiveFile("linux", "amd64"),
		LinuxAmd64Sha:   shas["linux/amd64"],
	}

	tmpl, err := template.New("formula").Parse(formulaTemplate)
	if err != nil {
		return "", fmt.Errorf("parse formula template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render formula: %w", err)
	}
	return buf.String(), nil
}

// formulaClassName converts a lowercase compound project name (e.g.
// "iamspectre") into Homebrew's expected Formula class name ("Iamspectre").
func formulaClassName(projectName string) string {
	if projectName == "" {
		return projectName
	}
	return strings.ToUpper(projectName[:1]) + projectName[1:]
}

// ParseChecksums parses GoReleaser's checksums.txt format
// ("<sha256>  <filename>" per line) into a filename -> sha256 map.
func ParseChecksums(data string) (map[string]string, error) {
	sums := map[string]string{}
	for lineNum, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("checksums.txt line %d: expected \"<sha256> <filename>\", got %q", lineNum+1, line)
		}
		sums[fields[1]] = fields[0]
	}
	return sums, nil
}
