package release

import (
	"regexp"
	"strings"
	"testing"
)

func testChecksums() map[string]string {
	return map[string]string{
		"iamspectre_1.2.3_darwin_arm64.tar.gz": "aaaa000000000000000000000000000000000000000000000000000000aaaa",
		"iamspectre_1.2.3_darwin_amd64.tar.gz": "bbbb000000000000000000000000000000000000000000000000000000bbbb",
		"iamspectre_1.2.3_linux_arm64.tar.gz":  "cccc000000000000000000000000000000000000000000000000000000cccc",
		"iamspectre_1.2.3_linux_amd64.tar.gz":  "dddd000000000000000000000000000000000000000000000000000000dddd",
		"iamspectre_1.2.3_windows_amd64.zip":   "eeee000000000000000000000000000000000000000000000000000000eeee",
	}
}

func testFormulaInput() FormulaInput {
	return FormulaInput{
		ProjectName: "iamspectre",
		Version:     "1.2.3",
		Homepage:    "https://github.com/ppiankov/iamspectre",
		Description: "Cross-cloud IAM auditor",
		License:     "MIT",
		RepoOwner:   "ppiankov",
		Checksums:   testChecksums(),
	}
}

// WO-96: the rendered Formula must keep the explicit-version, install, and
// test contract the deprecated `brews` publisher used to guarantee, across
// all four macOS/Linux amd64/arm64 archives.
func TestRenderFormula(t *testing.T) {
	got, err := RenderFormula(testFormulaInput())
	if err != nil {
		t.Fatalf("RenderFormula: %v", err)
	}

	want := `class Iamspectre < Formula
  desc "Cross-cloud IAM auditor"
  homepage "https://github.com/ppiankov/iamspectre"
  version "1.2.3"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ppiankov/iamspectre/releases/download/v1.2.3/iamspectre_1.2.3_darwin_arm64.tar.gz"
      sha256 "aaaa000000000000000000000000000000000000000000000000000000aaaa"
    end
    on_intel do
      url "https://github.com/ppiankov/iamspectre/releases/download/v1.2.3/iamspectre_1.2.3_darwin_amd64.tar.gz"
      sha256 "bbbb000000000000000000000000000000000000000000000000000000bbbb"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ppiankov/iamspectre/releases/download/v1.2.3/iamspectre_1.2.3_linux_arm64.tar.gz"
      sha256 "cccc000000000000000000000000000000000000000000000000000000cccc"
    end
    on_intel do
      url "https://github.com/ppiankov/iamspectre/releases/download/v1.2.3/iamspectre_1.2.3_linux_amd64.tar.gz"
      sha256 "dddd000000000000000000000000000000000000000000000000000000dddd"
    end
  end

  def install
    bin.install "iamspectre"
  end

  test do
    system "#{bin}/iamspectre", "version"
  end
end
`
	if got != want {
		t.Fatalf("RenderFormula mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderFormulaMissingChecksum(t *testing.T) {
	in := testFormulaInput()
	delete(in.Checksums, "iamspectre_1.2.3_linux_arm64.tar.gz")

	_, err := RenderFormula(in)
	if err == nil {
		t.Fatal("expected error for missing linux/arm64 checksum, got nil")
	}
	if !strings.Contains(err.Error(), "iamspectre_1.2.3_linux_arm64.tar.gz") {
		t.Fatalf("error = %q, want it to name the missing archive", err.Error())
	}
}

// WO-140: an unsafe free-text field must fail closed rather than emit a
// malformed Ruby string literal.
func TestRenderFormulaRejectsUnsafeField(t *testing.T) {
	in := testFormulaInput()
	in.Description = `auditor" then "injected`
	if _, err := RenderFormula(in); err == nil {
		t.Fatal("expected error for description containing a double-quote, got nil")
	}

	in = testFormulaInput()
	in.Homepage = "https://example.com/\nmalicious"
	if _, err := RenderFormula(in); err == nil {
		t.Fatal("expected error for homepage containing a newline, got nil")
	}
}

// WO-140: an invalid version must fail closed and name the offending value,
// because it also feeds the releases/download/v<version>/ URL path.
func TestRenderFormulaRejectsInvalidVersion(t *testing.T) {
	// WO-150: assert on validate() directly. RenderFormula would also error via a
	// checksum miss on the bad-version archive filename, masking whether the
	// version-pattern check actually fired.
	in := testFormulaInput()
	in.Version = "1.2.3 bad"
	err := in.validate()
	if err == nil {
		t.Fatal("expected error for invalid version, got nil")
	}
	if !strings.Contains(err.Error(), "1.2.3 bad") {
		t.Fatalf("error = %q, want it to name the offending version", err.Error())
	}

	// A version carrying a double-quote must also fail closed — it would break
	// both the Ruby `version` string and the download URL.
	in = testFormulaInput()
	in.Version = `1.2.3"`
	if err := in.validate(); err == nil {
		t.Fatal("expected error for version containing a double-quote, got nil")
	}
}

// WO-143: a free-text field carrying a Ruby string-interpolation sequence
// (#{...}) must be rejected — the WO-140 denylist let it through, which would
// execute arbitrary Ruby at `brew install` time.
func TestRenderFormulaRejectsRubyInterpolation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*FormulaInput)
	}{
		{"description", func(in *FormulaInput) { in.Description = `auditor #{system("id")}` }},
		{"homepage", func(in *FormulaInput) { in.Homepage = `https://example.com/#{x}` }},
		{"license", func(in *FormulaInput) { in.License = `MIT #{x}` }},
		{"repo owner", func(in *FormulaInput) { in.RepoOwner = `ppiankov#{x}` }},
	} {
		in := testFormulaInput()
		tc.apply(&in)
		if _, err := RenderFormula(in); err == nil {
			t.Fatalf("%s: expected error for Ruby interpolation #{...}, got nil", tc.name)
		}
	}
}

// WO-143: the real default description (cmd/publish-homebrew-formula) contains
// an em dash — a non-ASCII graphic rune. The allowlist must accept it, or live
// releases break. Guards against an over-tightening to ASCII-only.
func TestRenderFormulaAllowsNonASCIIDescription(t *testing.T) {
	in := testFormulaInput()
	in.Description = "Cross-cloud IAM auditor — finds unused, over-permissioned, and stale identities"
	out, err := RenderFormula(in)
	if err != nil {
		t.Fatalf("RenderFormula rejected the default em-dash description: %v", err)
	}
	if !strings.Contains(out, "—") {
		t.Fatal("rendered formula dropped the em dash from the description")
	}
}

// WO-147: invalid UTF-8 bytes decode to U+FFFD (graphic) and slip past the rune
// allowlist; they must be rejected explicitly rather than rendered raw.
func TestRenderFormulaRejectsInvalidUTF8(t *testing.T) {
	in := testFormulaInput()
	in.Description = "auditor \xc0\xa3" // 0xC0 0xA3: invalid/overlong UTF-8
	if _, err := RenderFormula(in); err == nil {
		t.Fatal("expected error for description with invalid UTF-8, got nil")
	}
}

// WO-143: ProjectName is spliced unquoted into the class declaration, so any
// character outside the letters/digits/hyphen allowlist must fail closed.
func TestRenderFormulaRejectsProjectNameInjection(t *testing.T) {
	for _, bad := range []string{
		`iamspectre; system("id")`,
		`iamspectre" < Formula; end; system("id"); class X`,
		"iamspectre\nclass Evil",
		"iam spectre",
		"",
	} {
		in := testFormulaInput()
		in.ProjectName = bad
		if _, err := RenderFormula(in); err == nil {
			t.Fatalf("expected error for project name %q, got nil", bad)
		}
	}
}

// WO-148: every ProjectName accepted by validate() must yield a syntactically
// valid Ruby class name once passed through formulaClassName.
func TestFormulaProjectNameProducesValidClass(t *testing.T) {
	validRubyClass := regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	for _, name := range []string{"iamspectre", "Tool2", "abc"} {
		in := testFormulaInput()
		in.ProjectName = name
		if err := in.validate(); err != nil {
			t.Fatalf("validate rejected valid project name %q: %v", name, err)
		}
		if cn := formulaClassName(name); !validRubyClass.MatchString(cn) {
			t.Fatalf("project name %q produced invalid Ruby class name %q", name, cn)
		}
	}
}

// WO-148: a leading digit, an embedded hyphen, or an underscore would produce an
// invalid Ruby class declaration and must be rejected.
func TestRenderFormulaRejectsInvalidProjectNameShape(t *testing.T) {
	for _, bad := range []string{"1foo", "9", "foo-bar", "foo_bar"} {
		in := testFormulaInput()
		in.ProjectName = bad
		// WO-149: call validate() directly. RenderFormula would also error via a
		// checksum miss on the bad-name archive filename, which would mask whether
		// the shape check actually fired.
		if err := in.validate(); err == nil {
			t.Fatalf("expected error for project name %q, got nil", bad)
		}
	}
}

// WO-148 (residual gap found in review, verified with `ruby -c`): formulaClassName
// only uppercases the first byte, so a ProjectName that is already all-uppercase
// passes through unchanged. "BEGIN" and "END" are Ruby's only all-caps reserved
// keywords, so `class BEGIN < Formula` / `class END < Formula` is a syntax error
// even though the shape regex (leading letter, letters/digits only) accepts them.
// "bEGIN" must also be rejected: capitalizing its first letter also yields "BEGIN".
func TestRenderFormulaRejectsReservedRubyClassName(t *testing.T) {
	for _, bad := range []string{"BEGIN", "END", "bEGIN"} {
		in := testFormulaInput()
		in.ProjectName = bad
		// WO-149: call validate() directly so the reserved-keyword check is what
		// rejects the input, not a downstream checksum miss on the bad-name archive.
		if err := in.validate(); err == nil {
			t.Fatalf("expected error for reserved-keyword project name %q, got nil", bad)
		}
	}

	// Every other Ruby keyword is lowercase, so capitalizing its first letter
	// yields a distinct, non-reserved constant and must still be accepted.
	for _, ok := range []string{"class", "def", "end", "module"} {
		in := testFormulaInput()
		in.ProjectName = ok
		if err := in.validate(); err != nil {
			t.Fatalf("validate rejected valid project name %q: %v", ok, err)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	input := "aaaa  iamspectre_1.2.3_darwin_arm64.tar.gz\n" +
		"bbbb  iamspectre_1.2.3_darwin_amd64.tar.gz\n" +
		"\n"

	got, err := ParseChecksums(input)
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}
	want := map[string]string{
		"iamspectre_1.2.3_darwin_arm64.tar.gz": "aaaa",
		"iamspectre_1.2.3_darwin_amd64.tar.gz": "bbbb",
	}
	if len(got) != len(want) {
		t.Fatalf("ParseChecksums returned %d entries, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("ParseChecksums[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseChecksumsMalformedLine(t *testing.T) {
	_, err := ParseChecksums("not-a-valid-line-with-three fields here\n")
	if err == nil {
		t.Fatal("expected error for malformed checksums line, got nil")
	}
}
