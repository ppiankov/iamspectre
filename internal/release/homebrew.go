// Package release holds the release-engineering contracts and helpers that
// back .github/workflows/release.yml and .goreleaser.yml.
package release

import (
	"bytes"
	"fmt"
	"regexp"
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
	// WO-140: fail closed on inputs that would break the rendered Ruby string
	// literals or the releases/download/v<version>/ URL path — text/template
	// performs no Ruby-context escaping, so validation is the only guard.
	if err := in.validate(); err != nil {
		return "", err
	}

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

// WO-140: formulaVersionPattern accepts a leading-"v"-stripped semver. A
// version outside this shape could inject characters into the Ruby `version`
// string or, worse, into the releases/download/v<version>/ download URL.
var formulaVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// WO-140: validate rejects FormulaInput values that cannot be rendered safely.
// Version must be clean semver; every free-text field interpolated into a Ruby
// double-quoted string must be free of quotes, backslashes, and control
// characters. It fails closed with an error naming the offending value rather
// than emitting a malformed Formula.
func (in FormulaInput) validate() error {
	if !formulaVersionPattern.MatchString(in.Version) {
		return fmt.Errorf("invalid version %q: expected semver without a leading v (e.g. 1.2.3)", in.Version)
	}
	for _, f := range []struct{ name, value string }{
		{"project name", in.ProjectName},
		{"homepage", in.Homepage},
		{"description", in.Description},
		{"license", in.License},
		{"repo owner", in.RepoOwner},
	} {
		if strings.IndexFunc(f.value, unsafeFormulaRune) >= 0 {
			return fmt.Errorf("invalid %s %q: contains a character that cannot be safely rendered into the Formula", f.name, f.value)
		}
	}
	return nil
}

// WO-140: unsafeFormulaRune reports runes that would break a Ruby
// double-quoted string literal — a double-quote, a backslash, or any control
// character (newlines and the DEL byte included).
func unsafeFormulaRune(r rune) bool {
	return r == '"' || r == '\\' || r < 0x20 || r == 0x7f
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
